#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_OFBIZ_51467_IMAGE:-vulhub/ofbiz:18.12.10}"
baseline_name="${OHMYRASP_VULHUB_OFBIZ_51467_BASELINE_NAME:-ohmyrasp-vulhub-ofbiz51467-baseline}"
protected_name="${OHMYRASP_VULHUB_OFBIZ_51467_PROTECTED_NAME:-ohmyrasp-vulhub-ofbiz51467-protected}"
baseline_port="${OHMYRASP_VULHUB_OFBIZ_51467_BASELINE_PORT:-18442}"
protected_port="${OHMYRASP_VULHUB_OFBIZ_51467_PROTECTED_PORT:-18443}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-ofbiz-18.12.10-51467-java8-baseline"
protected_dir="logs/vulhub-ofbiz-18.12.10-51467-java8-protected"
protected_log="${protected_dir}/events.jsonl"
exploit_path="/webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y"
exploit_body="groovyProgram=throw new Exception('id'.execute().text);"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl -k --max-time 30 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

wait_for_ofbiz() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "https://127.0.0.1:${port}/accounting")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "OFBiz container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "OFBiz did not expose /accounting at ${port}" >&2
  exit 1
}

post_programexport() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "$exploit_body" \
    "https://127.0.0.1:${port}${exploit_path}"
}

wait_for_protected_startup() {
  for attempt in $(seq 1 180); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in OFBiz protected container" >&2
  exit 1
}

command_block_count() {
  grep -Ec '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' \
    "$protected_log" || true
}

wait_for_command_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(command_block_count)"
    if (( count > previous )); then
      printf 'command_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_command_execution_exploit_primitive block event for OFBiz CVE-2023-51467" >&2
  exit 1
}

run_baseline() {
  docker run -d --name "$baseline_name" -p "${baseline_port}:8443" \
    "$image" >/dev/null

  wait_for_ofbiz "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(post_programexport "$baseline_port" "${baseline_dir}/programexport-id.response")"
  printf 'baseline_programexport_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] \
    || ! grep -Fq "java.lang.Exception: uid=0(root)" "${baseline_dir}/programexport-id.response"; then
    cat "${baseline_dir}/programexport-id.response" >&2 || true
    echo "baseline OFBiz did not return command output from ProgramExport Groovy" >&2
    exit 1
  fi

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" -p "${protected_port}:8443" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_ofbiz "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "OFBiz protected startup produced a detection before CVE-2023-51467 traffic" >&2
    exit 1
  fi

  local previous_count
  local status
  previous_count="$(command_block_count)"
  status="$(post_programexport "$protected_port" "${protected_dir}/programexport-id.response")"
  printf 'protected_programexport_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_command_block "$previous_count"
  if grep -Fq "java.lang.Exception: uid=0(root)" "${protected_dir}/programexport-id.response"; then
    cat "${protected_dir}/programexport-id.response" >&2 || true
    echo "protected OFBiz still returned command output from ProgramExport Groovy" >&2
    exit 1
  fi
  if ! grep -Fq "OhMyRASP Java 8 blocked suspicious command execution" \
    "${protected_dir}/programexport-id.response"; then
    cat "${protected_dir}/programexport-id.response" >&2 || true
    echo "protected OFBiz response did not include the Java 8 command block exception" >&2
    exit 1
  fi
}

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub OFBiz 18.12.10 CVE-2023-51467 Java8 acceptance passed"
