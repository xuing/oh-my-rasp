#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_JMETER_1297_IMAGE:-vulhub/jmeter:3.3}"
baseline_name="${OHMYRASP_VULHUB_JMETER_1297_BASELINE_NAME:-ohmyrasp-vulhub-jmeter1297-baseline}"
protected_name="${OHMYRASP_VULHUB_JMETER_1297_PROTECTED_NAME:-ohmyrasp-vulhub-jmeter1297-protected}"
baseline_port="${OHMYRASP_VULHUB_JMETER_1297_BASELINE_PORT:-19186}"
protected_port="${OHMYRASP_VULHUB_JMETER_1297_PROTECTED_PORT:-19187}"
payload_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
success_file="/tmp/ohmyrasp-jmeter1297-success"
baseline_dir="logs/vulhub-jmeter-2018-1297-java8-baseline"
protected_dir="logs/vulhub-jmeter-2018-1297-java8-protected"
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

prepare_ysoserial() {
  # shellcheck source=scripts/lib/ysoserial.sh
  source scripts/lib/ysoserial.sh
  prepare_ysoserial_jar "${payload_dir}/ysoserial.jar"
  return
  mkdir -p "$payload_dir"
  if [[ ! -s "${payload_dir}/ysoserial.jar" ]]; then
    rm -rf "${payload_dir}/src"
    docker run --rm -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
}

wait_for_rmi() {
  local name="$1"
  local port="$2"
  local dir="$3"

  for attempt in $(seq 1 90); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
      printf 'rmi_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose JMeter RMI on ${port}" >&2
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
  echo "missing Java8 agent startup event for JMeter CVE-2018-1297" >&2
  exit 1
}

run_beanshell_exploit() {
  local port="$1"
  local dir="$2"
  local attempt="${3:-1}"
  local output="${dir}/beanshell1-exploit-${attempt}.log"
  local status

  set +e
  docker run --rm --network host -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
    bash -lc "/usr/local/openjdk-8/bin/java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit 127.0.0.1 ${port} BeanShell1 'touch ${success_file}'" \
    > "$output" 2>&1
  status=$?
  set -e
  ln -sf "$(basename "$output")" "${dir}/beanshell1-exploit.log"
  printf 'exploit_attempt=%s exploit_status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:1099" \
    "$image" /usr/src/apache-jmeter-3.3/bin/jmeter-server \
      -Jserver.rmi.ssl.disable=true >/dev/null
  wait_for_rmi "$baseline_name" "$baseline_port" "$baseline_dir"
  sleep "${OHMYRASP_JMETER_RMI_SETTLE_SECONDS:-8}"
}

start_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:1099" \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/tmp/ohmyrasp-logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/tmp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/tmp/ohmyrasp-logs/events.jsonl -Dohmyrasp.java8.block=true -Djmeter.home=/usr/src/apache-jmeter-3.3" \
    "$image" /usr/src/apache-jmeter-3.3/bin/jmeter-server \
      -Jserver.rmi.ssl.disable=true >/dev/null
  wait_for_rmi "$protected_name" "$protected_port" "$protected_dir"
  wait_for_protected_startup
  sleep "${OHMYRASP_JMETER_RMI_SETTLE_SECONDS:-8}"
}

run_baseline() {
  start_baseline
  docker exec "$baseline_name" rm -f "$success_file"

  for exploit_attempt in $(seq 1 8); do
    run_beanshell_exploit "$baseline_port" "$baseline_dir" "$exploit_attempt"
    for marker_attempt in $(seq 1 5); do
      if docker exec "$baseline_name" test -e "$success_file"; then
        printf 'baseline_exploit_attempt=%s baseline_marker_attempt=%s\n' "$exploit_attempt" "$marker_attempt" >> "${baseline_dir}/attempts.log"
        copy_artifacts "$baseline_name" "$baseline_dir"
        docker rm -f "$baseline_name" >/dev/null 2>&1 || true
        return
      fi
      sleep 1
    done
    sleep 3
  done

  docker logs "$baseline_name" >&2 || true
  cat "${baseline_dir}/beanshell1-exploit.log" >&2 || true
  echo "baseline JMeter CVE-2018-1297 did not execute the BeanShell1 payload" >&2
  exit 1
}

run_protected() {
  start_protected
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected JMeter container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  for exploit_attempt in $(seq 1 8); do
    run_beanshell_exploit "$protected_port" "$protected_dir" "$exploit_attempt"
    sleep 2

    if docker exec "$protected_name" test -e "$success_file"; then
      echo "protected JMeter CVE-2018-1297 created ${success_file} despite Java8 RASP" >&2
      exit 1
    fi
    if grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
      printf 'protected_block_attempt=%s\n' "$exploit_attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 3
  done

  cat "$protected_log" >&2 || true
  docker logs "$protected_name" >&2 || true
  echo "missing java8_deserialization_gadget_class block event for JMeter CVE-2018-1297" >&2
  exit 1
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

prepare_ysoserial
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub JMeter CVE-2018-1297 Java8 acceptance passed"
