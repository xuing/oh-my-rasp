#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_ROCKETMQ_IMAGE:-vulhub/rocketmq:5.1.0}"
attack_image="${OHMYRASP_VULHUB_ROCKETMQ_ATTACK_IMAGE:-eclipse-temurin:8-jre}"
attack_jar="${OHMYRASP_VULHUB_ROCKETMQ_ATTACK_JAR:-/tmp/ohmyrasp-rocketmq-attack/rocketmq-attack-1.0-SNAPSHOT.jar}"
baseline_name="${OHMYRASP_VULHUB_ROCKETMQ_BASELINE_NAME:-ohmyrasp-vulhub-rocketmq-33246-baseline}"
protected_name="${OHMYRASP_VULHUB_ROCKETMQ_PROTECTED_NAME:-ohmyrasp-vulhub-rocketmq-33246-protected}"
baseline_port="${OHMYRASP_VULHUB_ROCKETMQ_BASELINE_PORT:-19086}"
protected_port="${OHMYRASP_VULHUB_ROCKETMQ_PROTECTED_PORT:-19087}"
marker="${OHMYRASP_VULHUB_ROCKETMQ_MARKER:-/tmp/ohmyrasp-rocketmq33246-success}"
attack_timeout="${OHMYRASP_VULHUB_ROCKETMQ_ATTACK_TIMEOUT:-120}"
baseline_dir="logs/vulhub-rocketmq-2023-33246-java8-baseline"
protected_dir="logs/vulhub-rocketmq-2023-33246-java8-protected"
protected_log="${protected_dir}/events.jsonl"

if [[ ! -f "$attack_jar" ]]; then
  echo "missing rocketmq-attack jar at ${attack_jar}" >&2
  echo "download it from https://github.com/vulhub/rocketmq-attack/releases/tag/1.0 or set OHMYRASP_VULHUB_ROCKETMQ_ATTACK_JAR" >&2
  exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout command is required for the RocketMQ attack runner" >&2
  exit 1
fi

attack_dir="$(cd "$(dirname "$attack_jar")" && pwd)"
attack_file="$(basename "$attack_jar")"

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
  docker rm -f \
    "$baseline_name" \
    "$protected_name" \
    "${baseline_name}-attack" \
    "${protected_name}-attack" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_rocketmq() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 90); do
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    printf 'ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if grep -Eq 'startup successfully|boot success' "${dir}/container.log"; then
      return
    fi
    sleep 2
  done
  cat "${dir}/container.log" >&2 || true
  echo "RocketMQ did not become ready for ${name}" >&2
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
  echo "missing Java8 agent startup event for RocketMQ protected container" >&2
  exit 1
}

run_attack() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local attack_name="${name}-attack"
  docker rm -f "$attack_name" >/dev/null 2>&1 || true
  set +e
  timeout "$attack_timeout" docker run --rm --name "$attack_name" --network host \
    -v "${attack_dir}:/attack:ro" \
    "$attack_image" \
    java -jar "/attack/${attack_file}" AttackBroker \
    --target "127.0.0.1:${port}" \
    --cmd "touch ${marker}" \
    > "${dir}/attack.out" 2> "${dir}/attack.err"
  local status=$?
  set -e
  printf 'attack_status=%s\n' "$status" >> "${dir}/attempts.log"
  if [[ "$status" != "0" ]]; then
    cat "${dir}/attack.out" >&2 || true
    cat "${dir}/attack.err" >&2 || true
    echo "RocketMQ attack tool exited with status ${status}" >&2
    exit 1
  fi
}

wait_for_marker() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 90); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if docker exec "$name" test -f "$marker"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  cat "${dir}/attack.out" >&2 || true
  cat "${dir}/attack.err" >&2 || true
  echo "baseline RocketMQ did not create ${marker}" >&2
  exit 1
}

wait_for_block_without_marker() {
  local saw_block="no"
  for attempt in $(seq 1 120); do
    printf 'protected_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if docker exec "$protected_name" test -f "$marker"; then
      docker logs "$protected_name" >&2 || true
      cat "$protected_log" >&2 || true
      echo "protected RocketMQ still created ${marker}" >&2
      exit 1
    fi
    if grep -Eq '"algorithm":"java8_command_execution_shell_meta".*"action":"block"' "$protected_log"; then
      saw_block="yes"
      break
    fi
    sleep 1
  done
  if [[ "$saw_block" != "yes" ]]; then
    cat "$protected_log" >&2 || true
    cat "${protected_dir}/attack.out" >&2 || true
    cat "${protected_dir}/attack.err" >&2 || true
    echo "missing java8_command_execution_shell_meta block event for RocketMQ CVE-2023-33246" >&2
    exit 1
  fi
  if docker exec "$protected_name" test -f "$marker"; then
    cat "$protected_log" >&2 || true
    echo "protected RocketMQ created ${marker} after the block event" >&2
    exit 1
  fi
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:10911" \
    "$image" >/dev/null

  wait_for_rocketmq "$baseline_name" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$marker"
  run_attack "$baseline_name" "$baseline_port" "$baseline_dir"
  wait_for_marker "$baseline_name" "$baseline_dir"
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:10911" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_OPT_EXT=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_rocketmq "$protected_name" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "RocketMQ protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$marker"
  run_attack "$protected_name" "$protected_port" "$protected_dir"
  wait_for_block_without_marker
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" "${baseline_name}-attack" "${protected_name}-attack" >/dev/null 2>&1 || true

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub RocketMQ CVE-2023-33246 Java8 acceptance passed"
