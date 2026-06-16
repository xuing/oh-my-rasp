#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_ROCKETMQ_37582_IMAGE:-vulhub/rocketmq:5.1.0}"
attack_image="${OHMYRASP_VULHUB_ROCKETMQ_37582_ATTACK_IMAGE:-eclipse-temurin:8-jre}"
attack_jar="${OHMYRASP_VULHUB_ROCKETMQ_37582_ATTACK_JAR:-/tmp/ohmyrasp-rocketmq-attack/rocketmq-attack-1.1-SNAPSHOT.jar}"
attack_jar_url="${OHMYRASP_VULHUB_ROCKETMQ_37582_ATTACK_JAR_URL:-https://github.com/vulhub/rocketmq-attack/releases/download/1.1/rocketmq-attack-1.1-SNAPSHOT.jar}"
attack_jar_sha256="${OHMYRASP_VULHUB_ROCKETMQ_37582_ATTACK_JAR_SHA256:-4a6a96fad560ae9054204fd758d61b954111ebe7bfe0877b6a4ac1ed588e7085}"
baseline_name="${OHMYRASP_VULHUB_ROCKETMQ_37582_BASELINE_NAME:-ohmyrasp-vulhub-rocketmq-37582-baseline}"
protected_name="${OHMYRASP_VULHUB_ROCKETMQ_37582_PROTECTED_NAME:-ohmyrasp-vulhub-rocketmq-37582-protected}"
baseline_port="${OHMYRASP_VULHUB_ROCKETMQ_37582_BASELINE_PORT:-19088}"
protected_port="${OHMYRASP_VULHUB_ROCKETMQ_37582_PROTECTED_PORT:-19089}"
marker_file="${OHMYRASP_VULHUB_ROCKETMQ_37582_MARKER_FILE:-/tmp/../tmp/ohmyrasp-rocketmq37582-success.sh}"
marker_real_path="${OHMYRASP_VULHUB_ROCKETMQ_37582_MARKER_REAL_PATH:-/tmp/ohmyrasp-rocketmq37582-success.sh}"
marker_content="${OHMYRASP_VULHUB_ROCKETMQ_37582_MARKER_CONTENT:-ohmyrasp-rocketmq37582}"
attack_timeout="${OHMYRASP_VULHUB_ROCKETMQ_37582_ATTACK_TIMEOUT:-120}"
baseline_dir="logs/vulhub-rocketmq-2023-37582-java8-baseline"
protected_dir="logs/vulhub-rocketmq-2023-37582-java8-protected"
protected_log="${protected_dir}/events.jsonl"

download_attack_jar() {
  if [[ -s "$attack_jar" ]]; then
    return
  fi
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to download rocketmq-attack jar; set OHMYRASP_VULHUB_ROCKETMQ_37582_ATTACK_JAR to a local file" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$attack_jar")"
  curl -fL --retry 3 --connect-timeout 20 -o "${attack_jar}.tmp" "$attack_jar_url"
  printf '%s  %s
' "$attack_jar_sha256" "${attack_jar}.tmp" | sha256sum -c -
  mv "${attack_jar}.tmp" "$attack_jar"
}

download_attack_jar

if ! command -v timeout >/dev/null 2>&1; then
  echo "timeout command is required for the RocketMQ NameServer attack runner" >&2
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

wait_for_namesrv() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 90); do
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    printf 'ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if grep -Eq 'The Name Server boot success|boot success|startup successfully' "${dir}/container.log"; then
      return
    fi
    sleep 2
  done
  cat "${dir}/container.log" >&2 || true
  echo "RocketMQ NameServer did not become ready for ${name}" >&2
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
  echo "missing Java8 agent startup event for RocketMQ NameServer protected container" >&2
  exit 1
}

run_attack() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local require_success="$4"
  local attack_name="${name}-attack"
  docker rm -f "$attack_name" >/dev/null 2>&1 || true
  set +e
  timeout "$attack_timeout" docker run --rm --name "$attack_name" --network host \
    -v "${attack_dir}:/attack:ro" \
    "$attack_image" \
    java -jar "/attack/${attack_file}" AttackNamesrv \
    --target "127.0.0.1:${port}" \
    --file "$marker_file" \
    --data "$marker_content" \
    > "${dir}/attack.out" 2> "${dir}/attack.err"
  local status=$?
  set -e
  printf 'attack_status=%s\n' "$status" >> "${dir}/attempts.log"
  if [[ "$require_success" == "yes" && "$status" != "0" ]]; then
    cat "${dir}/attack.out" >&2 || true
    cat "${dir}/attack.err" >&2 || true
    echo "RocketMQ NameServer attack tool exited with status ${status}" >&2
    exit 1
  fi
}

wait_for_marker_content() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 30); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if docker exec "$name" test -f "$marker_real_path"; then
      if docker exec "$name" grep -Fq "$marker_content" "$marker_real_path"; then
        return
      fi
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  cat "${dir}/attack.out" >&2 || true
  cat "${dir}/attack.err" >&2 || true
  echo "baseline RocketMQ NameServer did not write expected marker content" >&2
  exit 1
}

wait_for_block_without_marker() {
  local saw_block="no"
  for attempt in $(seq 1 60); do
    printf 'protected_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if docker exec "$protected_name" test -f "$marker_real_path"; then
      if docker exec "$protected_name" grep -Fq "$marker_content" "$marker_real_path"; then
        docker logs "$protected_name" >&2 || true
        cat "$protected_log" >&2 || true
        echo "protected RocketMQ NameServer still wrote marker content" >&2
        exit 1
      fi
    fi
    if grep -Eq '"algorithm":"java8_file_script_write".*"action":"block"' "$protected_log"; then
      saw_block="yes"
      break
    fi
    sleep 1
  done
  if [[ "$saw_block" != "yes" ]]; then
    cat "$protected_log" >&2 || true
    cat "${protected_dir}/attack.out" >&2 || true
    cat "${protected_dir}/attack.err" >&2 || true
    echo "missing java8_file_script_write block event for RocketMQ CVE-2023-37582" >&2
    exit 1
  fi
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:9876" \
    "$image" mqnamesrv >/dev/null

  wait_for_namesrv "$baseline_name" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$marker_real_path" "$marker_file" || true
  run_attack "$baseline_name" "$baseline_port" "$baseline_dir" yes
  wait_for_marker_content "$baseline_name" "$baseline_dir"
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:9876" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_OPT_EXT=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" mqnamesrv >/dev/null

  wait_for_protected_startup
  wait_for_namesrv "$protected_name" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "RocketMQ NameServer protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$marker_real_path" "$marker_file" || true
  run_attack "$protected_name" "$protected_port" "$protected_dir" no
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

echo "vulhub RocketMQ CVE-2023-37582 Java8 acceptance passed"
