#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_COLDFUSION_26360_IMAGE:-vulhub/coldfusion:2018.0.15}"
baseline_name="${OHMYRASP_VULHUB_COLDFUSION_26360_BASELINE_NAME:-ohmyrasp-coldfusion26360-baseline}"
protected_name="${OHMYRASP_VULHUB_COLDFUSION_26360_PROTECTED_NAME:-ohmyrasp-coldfusion26360-protected}"
baseline_port="${OHMYRASP_VULHUB_COLDFUSION_26360_BASELINE_PORT:-19500}"
protected_port="${OHMYRASP_VULHUB_COLDFUSION_26360_PROTECTED_PORT:-19501}"
protected_debug_port="${OHMYRASP_VULHUB_COLDFUSION_26360_PROTECTED_DEBUG_PORT:-19505}"
host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"
baseline_dir="logs/vulhub-coldfusion-2018.0.15-26360-java11-baseline"
protected_dir="logs/vulhub-coldfusion-2018.0.15-26360-java11-protected"
payload_dir="logs/vulhub-coldfusion-2018.0.15-26360-java11-payload"
protected_log="${protected_dir}/events.jsonl"
payload='{"_metadata":{"classname":"../../../../../../../../proc/self/environ"}}'

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
    echo "ColdFusion CVE-2023-26360 image did not report a Java 11 runtime" >&2
    exit 1
  fi
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8500" \
    -e password=vulhub \
    -e acceptEULA=YES \
    "$image" >/dev/null
}

start_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8500" \
    -p "${protected_debug_port}:5005" \
    -e password=vulhub \
    -e acceptEULA=YES \
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

send_metadata_lfi() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -G \
    --data-urlencode "_variables=${payload}" \
    "http://127.0.0.1:${port}/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?method=foo&_cfclient=true"
}

response_contains_environment() {
  local file="$1"
  tr '\000' '\n' < "$file" | grep -Fq 'USER=cfuser'
}

file_read_block_count() {
  grep -Ec '"hook":"FileInputStream.open".*"algorithm":"java11_file_sensitive_read".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_file_read_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(file_read_block_count)"
    if (( count > previous )); then
      printf 'file_read_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java11_file_sensitive_read block event for ColdFusion CVE-2023-26360" >&2
  exit 1
}

assert_protected_startup_quiet() {
  if ! grep -Fq '"request_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 11 request hook startup marker in protected ColdFusion container" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected ColdFusion produced a detection before metadata classname traffic" >&2
    exit 1
  fi
}

run_baseline() {
  start_baseline
  wait_for_coldfusion "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(send_metadata_lfi "$baseline_port" "${baseline_dir}/environ.response")"
  printf 'baseline_lfi_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if ! response_contains_environment "${baseline_dir}/environ.response"; then
    cat "${baseline_dir}/environ.response" >&2 || true
    echo "baseline ColdFusion CVE-2023-26360 did not disclose /proc/self/environ" >&2
    exit 1
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  start_protected
  wait_for_coldfusion "$protected_name" "$protected_port" "$protected_dir" true
  assert_protected_startup_quiet

  local previous_count status
  previous_count="$(file_read_block_count)"
  status="$(send_metadata_lfi "$protected_port" "${protected_dir}/environ.response")"
  printf 'protected_lfi_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if response_contains_environment "${protected_dir}/environ.response"; then
    cat "${protected_dir}/environ.response" >&2 || true
    echo "protected ColdFusion CVE-2023-26360 still disclosed /proc/self/environ" >&2
    exit 1
  fi
  wait_for_file_read_block "$previous_count"
  if ! grep -Fq '/proc/self/environ' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "ColdFusion CVE-2023-26360 block event did not record /proc/self/environ" >&2
    exit 1
  fi
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar >/dev/null

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

echo "vulhub ColdFusion 2018.0.15 CVE-2023-26360 Java11 acceptance passed"
