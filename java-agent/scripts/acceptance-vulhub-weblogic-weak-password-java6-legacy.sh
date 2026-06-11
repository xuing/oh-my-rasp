#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
vulhub_dir="${OHMYRASP_VULHUB_WEBLOGIC_WEAK_PASSWORD_DIR:-/tmp/vulhub-ohmyrasp-20260603/weblogic/weak_password}"
image="${OHMYRASP_VULHUB_WEBLOGIC_WEAK_PASSWORD_IMAGE:-vulhub/weblogic:10.3.6.0-2017}"
baseline_name="${OHMYRASP_VULHUB_WEBLOGIC_WEAK_PASSWORD_BASELINE_NAME:-ohmyrasp-weblogic-weak-password-baseline}"
baseline_port="${OHMYRASP_VULHUB_WEBLOGIC_WEAK_PASSWORD_BASELINE_PORT:-19650}"
baseline_dir="logs/vulhub-weblogic-weak-password-java6-baseline"
protected_dir="logs/vulhub-weblogic-weak-password-java6-protected"
web_dir="${vulhub_dir}/web"

copy_artifacts() {
  mkdir -p "$baseline_dir"
  if docker inspect "$baseline_name" >/dev/null 2>&1; then
    docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

verify_java6_boundary() {
  docker run --rm --entrypoint bash "$image" -lc \
    '"$JAVA16_HOME/bin/java" -version' > "${protected_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'java version "1.6.0_45"' "${protected_dir}/image-java-version.txt"; then
    cat "${protected_dir}/image-java-version.txt" >&2 || true
    echo "WebLogic weak-password image did not report the expected Java 6 runtime" >&2
    exit 1
  fi

  set +e
  docker run --rm --entrypoint bash \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    "$image" -lc '"$JAVA16_HOME/bin/java" -javaagent:/tmp/ohmyrasp-agent-java8.jar -version' \
    > "${protected_dir}/java8-agent-on-java6.log" 2>&1
  local status="$?"
  set -e
  printf 'java8_agent_on_java6_status=%s\n' "$status" > "${protected_dir}/attempts.log"
  if ! grep -Fq 'Unsupported major.minor version 52.0' "${protected_dir}/java8-agent-on-java6.log"; then
    cat "${protected_dir}/java8-agent-on-java6.log" >&2 || true
    echo "Java 6 WebLogic did not reject the Java 8 agent with the expected class-version error" >&2
    exit 1
  fi
}

wait_for_file_read() {
  local status
  for attempt in $(seq 1 240); do
    status="$(curl_status "${baseline_dir}/file-read-${attempt}.txt" \
      -G --data-urlencode 'path=/etc/passwd' \
      "http://127.0.0.1:${baseline_port}/hello/file.jsp")"
    printf 'file_read_attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if [[ "$status" == "200" ]] && grep -Fq 'root:x:0:0:' "${baseline_dir}/file-read-${attempt}.txt"; then
      cp "${baseline_dir}/file-read-${attempt}.txt" "${baseline_dir}/file-read-passwd.txt"
      return
    fi
    sleep 2
  done

  docker logs "$baseline_name" >&2 || true
  echo "baseline WebLogic weak-password file-read endpoint did not disclose /etc/passwd" >&2
  exit 1
}

mkdir -p /tmp/ohmyrasp-gradle-cache
docker run --rm -u "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/tmp/gradle-cache \
  -v /tmp/ohmyrasp-gradle-cache:/tmp/gradle-cache \
  -v "$(pwd):/workspace" \
  -w /workspace \
  gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

if [[ ! -d "$web_dir" ]]; then
  echo "missing Vulhub weak-password web directory: ${web_dir}" >&2
  exit 1
fi

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

verify_java6_boundary

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:7001" \
  -v "${web_dir}:/root/Oracle/Middleware/user_projects/domains/base_domain/autodeploy:ro" \
  "$image" >/dev/null

wait_for_file_read
copy_artifacts
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

echo "vulhub WebLogic weak-password Java6 legacy boundary passed"
