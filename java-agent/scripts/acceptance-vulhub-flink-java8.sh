#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_FLINK_IMAGE:-vulhub/flink:1.11.2}"
baseline_name="${OHMYRASP_VULHUB_FLINK_BASELINE_NAME:-ohmyrasp-vulhub-flink-17518-baseline}"
protected_name="${OHMYRASP_VULHUB_FLINK_PROTECTED_NAME:-ohmyrasp-vulhub-flink-17518-protected}"
baseline_port="${OHMYRASP_VULHUB_FLINK_BASELINE_PORT:-19108}"
protected_port="${OHMYRASP_VULHUB_FLINK_PROTECTED_PORT:-19109}"
marker_path="${OHMYRASP_VULHUB_FLINK_MARKER_PATH:-/tmp/ohmyrasp-flink17518-success.jar}"
upload_filename="${OHMYRASP_VULHUB_FLINK_UPLOAD_FILENAME:-../../../../../../tmp/ohmyrasp-flink17518-success.jar}"
marker_content="${OHMYRASP_VULHUB_FLINK_MARKER_CONTENT:-ohmyrasp-flink17518}"
baseline_dir="logs/vulhub-flink-2020-17518-java8-baseline"
protected_dir="logs/vulhub-flink-2020-17518-java8-protected"
protected_log="${protected_dir}/events.jsonl"

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

wait_for_flink() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl -sS -o "${dir}/ready-${attempt}.html" -w "%{http_code}" \
        "http://127.0.0.1:${port}/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Flink did not expose the REST UI at ${port}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java8 agent startup event for Flink protected container" >&2
  exit 1
}

upload_marker() {
  local port="$1"
  local dir="$2"
  printf '%s' "$marker_content" > "${dir}/payload.bin"
  curl -sS -o "${dir}/upload.response" -w "%{http_code}" \
    -F "jarfile=@${dir}/payload.bin;filename=${upload_filename}" \
    "http://127.0.0.1:${port}/jars/upload" || true
}

marker_matches() {
  local name="$1"
  docker exec "$name" test -f "$marker_path" \
    && docker exec "$name" grep -Fq "$marker_content" "$marker_path"
}

run_baseline() {
  local status
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8081" \
    "$image" jobmanager >/dev/null

  wait_for_flink "$baseline_name" "$baseline_port" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$marker_path" || true
  status="$(upload_marker "$baseline_port" "$baseline_dir")"
  printf 'upload_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  for attempt in $(seq 1 20); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
    if marker_matches "$baseline_name"; then
      copy_artifacts "$baseline_name" "$baseline_dir"
      docker rm -f "$baseline_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done
  cat "${baseline_dir}/upload.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline Flink did not write expected traversal marker content" >&2
  exit 1
}

run_protected() {
  local status
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8081" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "FLINK_ENV_JAVA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" jobmanager >/dev/null

  wait_for_protected_startup
  wait_for_flink "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Flink protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$marker_path" || true
  status="$(upload_marker "$protected_port" "$protected_dir")"
  printf 'upload_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  for attempt in $(seq 1 30); do
    printf 'protected_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if marker_matches "$protected_name"; then
      cat "$protected_log" >&2 || true
      echo "protected Flink still wrote marker content" >&2
      exit 1
    fi
    if grep -Eq '"algorithm":"java8_file_script_write".*"action":"block"' "$protected_log"; then
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/upload.response" >&2 || true
  echo "missing java8_file_script_write block event for Flink CVE-2020-17518" >&2
  exit 1
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
chmod 777 "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Flink CVE-2020-17518 Java8 acceptance passed"
