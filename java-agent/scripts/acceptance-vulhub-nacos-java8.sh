#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_NACOS_IMAGE:-vulhub/nacos:1.4.0}"
baseline_name="${OHMYRASP_VULHUB_NACOS_BASELINE_NAME:-ohmyrasp-vulhub-nacos-29442-baseline}"
protected_name="${OHMYRASP_VULHUB_NACOS_PROTECTED_NAME:-ohmyrasp-vulhub-nacos-29442-protected}"
baseline_port="${OHMYRASP_VULHUB_NACOS_BASELINE_PORT:-19084}"
protected_port="${OHMYRASP_VULHUB_NACOS_PROTECTED_PORT:-19085}"
vulhub_root="${OHMYRASP_VULHUB_ROOT:-/tmp/vulhub-ohmyrasp-20260603}"
poc_py="${OHMYRASP_VULHUB_NACOS_POC:-${vulhub_root}/nacos/CVE-2021-29442/poc.py}"
poc_timeout_seconds="${OHMYRASP_VULHUB_NACOS_POC_TIMEOUT_SECONDS:-120}"
protected_poc_timeout_seconds="${OHMYRASP_VULHUB_NACOS_PROTECTED_POC_TIMEOUT_SECONDS:-10}"
baseline_dir="logs/vulhub-nacos-2021-29442-java8-baseline"
protected_dir="logs/vulhub-nacos-2021-29442-java8-protected"
protected_log="${protected_dir}/events.jsonl"
protected_block_regex='"algorithm":"(java8_command_execution_exploit_primitive|java8_request_internal_identity)".*"action":"block"'

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

wait_for_nacos() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(
      curl --max-time 5 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/nacos/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] && grep -qi "nacos" "${dir}/ready-${attempt}.response"; then
      return
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "Nacos did not expose /nacos/ at ${port}" >&2
  exit 1
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
  echo "missing Java8 agent startup event for Nacos protected container" >&2
  exit 1
}

run_poc() {
  local port="$1"
  local command="$2"
  local output="$3"
  local allow_timeout="${4:-false}"
  local timeout_seconds="${5:-$poc_timeout_seconds}"
  if [[ ! -f "$poc_py" ]]; then
    echo "missing Vulhub Nacos poc.py at ${poc_py}" >&2
    exit 1
  fi
  if ! python3 - >/dev/null <<'PY'
import importlib.util
import sys

if importlib.util.find_spec("requests") is None:
    sys.exit(1)
PY
  then
    echo "python3 requests package is required for Vulhub Nacos poc.py" >&2
    exit 1
  fi
  local rc=0
  timeout --kill-after=5s "${timeout_seconds}s" \
    python3 "$poc_py" -t "http://127.0.0.1:${port}" -c "$command" > "$output" || rc=$?
  if [[ "$rc" == "0" ]]; then
    return 0
  fi
  if [[ "$allow_timeout" == "true" && "$rc" == "124" ]]; then
    printf '%s\n' \
      "poc timed out after ${timeout_seconds}s; continuing to verify protected block event" >> "$output"
    return 0
  fi
  cat "$output" >&2 || true
  echo "Nacos poc.py failed or timed out for port ${port} (exit=${rc})" >&2
  return "$rc"
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8848" \
    "$image" >/dev/null

  wait_for_nacos "$baseline_name" "$baseline_port" "$baseline_dir"
  run_poc "$baseline_port" "id" "${baseline_dir}/cve-2021-29442-poc.out"
  if ! grep -q "uid=0(root)" "${baseline_dir}/cve-2021-29442-poc.out"; then
    cat "${baseline_dir}/cve-2021-29442-poc.out" >&2 || true
    echo "baseline Nacos did not execute the Derby Java routine command" >&2
    exit 1
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8848" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_OPT=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_nacos "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Nacos protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  run_poc "$protected_port" "id" "${protected_dir}/cve-2021-29442-poc.out" true "$protected_poc_timeout_seconds"
  if grep -q "uid=0(root)" "${protected_dir}/cve-2021-29442-poc.out"; then
    cat "${protected_dir}/cve-2021-29442-poc.out" >&2 || true
    echo "protected Nacos still returned command output" >&2
    exit 1
  fi
  if ! grep -Eq "$protected_block_regex" "$protected_log"; then
    cat "$protected_log" >&2 || true
    cat "${protected_dir}/cve-2021-29442-poc.out" >&2 || true
    echo "missing command-execution or internal-identity block event for Nacos CVE-2021-29442" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Nacos CVE-2021-29442 Java8 acceptance passed"
