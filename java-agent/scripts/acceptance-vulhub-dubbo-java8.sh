#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_DUBBO_IMAGE:-vulhub/dubbo:2.7.3}"
zk_image="${OHMYRASP_VULHUB_DUBBO_ZK_IMAGE:-zookeeper:3.7.0}"
baseline_name="${OHMYRASP_VULHUB_DUBBO_BASELINE_NAME:-ohmyrasp-vulhub-dubbo-17564-baseline}"
baseline_zk_name="${OHMYRASP_VULHUB_DUBBO_BASELINE_ZK_NAME:-ohmyrasp-vulhub-dubbo-17564-baseline-zk}"
protected_name="${OHMYRASP_VULHUB_DUBBO_PROTECTED_NAME:-ohmyrasp-vulhub-dubbo-17564-protected}"
protected_zk_name="${OHMYRASP_VULHUB_DUBBO_PROTECTED_ZK_NAME:-ohmyrasp-vulhub-dubbo-17564-protected-zk}"
baseline_net="${OHMYRASP_VULHUB_DUBBO_BASELINE_NET:-ohmyrasp-vulhub-dubbo-17564-baseline-net}"
protected_net="${OHMYRASP_VULHUB_DUBBO_PROTECTED_NET:-ohmyrasp-vulhub-dubbo-17564-protected-net}"
baseline_port="${OHMYRASP_VULHUB_DUBBO_BASELINE_PORT:-19080}"
protected_port="${OHMYRASP_VULHUB_DUBBO_PROTECTED_PORT:-19081}"
baseline_zk_port="${OHMYRASP_VULHUB_DUBBO_BASELINE_ZK_PORT:-12181}"
protected_zk_port="${OHMYRASP_VULHUB_DUBBO_PROTECTED_ZK_PORT:-12182}"
payload_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
payload_file="${payload_dir}/dubbo-cc6-touch.ser"
success_file="/tmp/ohmyrasp-dubbo-success"
baseline_dir="logs/vulhub-dubbo-2019-17564-java8-baseline"
protected_dir="logs/vulhub-dubbo-2019-17564-java8-protected"
protected_log="${protected_dir}/events.jsonl"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_zk_name" "$baseline_dir/zookeeper"
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_zk_name" "$protected_dir/zookeeper"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f \
    "$baseline_name" "$baseline_zk_name" \
    "$protected_name" "$protected_zk_name" \
    >/dev/null 2>&1 || true
  docker network rm "$baseline_net" "$protected_net" >/dev/null 2>&1 || true
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
    bash -lc '/usr/local/openjdk-8/bin/java -jar ysoserial.jar CommonsCollections6 "touch /tmp/ohmyrasp-dubbo-success" > /work/dubbo-cc6-touch.ser && test -s /work/dubbo-cc6-touch.ser'
}

wait_for_zookeeper() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 120); do
    if docker exec "$name" sh -c 'printf "srvr" | nc -w 2 127.0.0.1 2181 | grep -q Zookeeper' \
        >/dev/null 2>&1; then
      printf 'zookeeper_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Zookeeper did not become ready for Dubbo CVE-2019-17564" >&2
  exit 1
}

wait_for_dubbo() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(
      curl --max-time 5 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" != "000" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Dubbo did not expose its HTTP protocol endpoint at ${port}" >&2
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
  echo "missing Java8 agent startup event for Dubbo protected container" >&2
  exit 1
}

post_payload() {
  local port="$1"
  local output="$2"
  local status
  status="$(
    curl --max-time 20 -sS -i -o "$output" -w "%{http_code}" \
      -H 'Content-Type: application/x-java-serialized-object' \
      --data-binary "@${payload_file}" \
      "http://127.0.0.1:${port}/org.vulhub.api.CalcService" 2>/dev/null || true
  )"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s' "$status"
}

start_stack() {
  local network="$1"
  local zk_name="$2"
  local app_name="$3"
  local app_port="$4"
  local zk_port="$5"
  local dir="$6"
  local mode="$7"

  docker network create "$network" >/dev/null
  docker run -d --name "$zk_name" \
    --network "$network" --network-alias zookeeper \
    -p "${zk_port}:2181" \
    "$zk_image" >/dev/null
  wait_for_zookeeper "$zk_name" "$dir/zookeeper"

  if [[ "$mode" == "protected" ]]; then
    docker run -d --name "$app_name" \
      --network "$network" \
      -p "${app_port}:8080" \
      -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
      -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
      -e DUBBO_REGISTRY=zookeeper://zookeeper:2181 \
      -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
      "$image" >/dev/null
    wait_for_protected_startup
  else
    docker run -d --name "$app_name" \
      --network "$network" \
      -p "${app_port}:8080" \
      -e DUBBO_REGISTRY=zookeeper://zookeeper:2181 \
      "$image" >/dev/null
  fi

  wait_for_dubbo "$app_name" "$app_port" "$dir"
}

run_baseline() {
  local status
  start_stack \
    "$baseline_net" "$baseline_zk_name" "$baseline_name" \
    "$baseline_port" "$baseline_zk_port" "$baseline_dir" "baseline"
  docker exec "$baseline_name" rm -f "$success_file"
  status="$(post_payload "$baseline_port" "${baseline_dir}/cve-2019-17564.response")"
  printf 'baseline_payload_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" == "000" ]]; then
    cat "${baseline_dir}/cve-2019-17564.response" >&2 || true
    echo "baseline Dubbo payload did not reach the HTTP endpoint" >&2
    exit 1
  fi
  for _ in $(seq 1 10); do
    if docker exec "$baseline_name" test -e "$success_file"; then
      copy_artifacts "$baseline_zk_name" "$baseline_dir/zookeeper"
      copy_artifacts "$baseline_name" "$baseline_dir"
      docker rm -f "$baseline_name" "$baseline_zk_name" >/dev/null 2>&1 || true
      docker network rm "$baseline_net" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done
  cat "${baseline_dir}/cve-2019-17564.response" >&2 || true
  echo "baseline Dubbo did not execute the CommonsCollections6 payload" >&2
  exit 1
}

run_protected() {
  local status
  start_stack \
    "$protected_net" "$protected_zk_name" "$protected_name" \
    "$protected_port" "$protected_zk_port" "$protected_dir" "protected"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Dubbo protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  status="$(post_payload "$protected_port" "${protected_dir}/cve-2019-17564.response")"
  printf 'protected_payload_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if [[ "$status" == "000" ]]; then
    cat "${protected_dir}/cve-2019-17564.response" >&2 || true
    echo "protected Dubbo payload did not reach the HTTP endpoint" >&2
    exit 1
  fi
  sleep 2
  if docker exec "$protected_name" test -e "$success_file"; then
    echo "protected Dubbo created ${success_file} despite Java8 RASP" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    cat "${protected_dir}/cve-2019-17564.response" >&2 || true
    echo "missing java8_deserialization_gadget_class block event for Dubbo CVE-2019-17564" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir/zookeeper" "$protected_dir/zookeeper"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f \
  "$baseline_name" "$baseline_zk_name" \
  "$protected_name" "$protected_zk_name" \
  >/dev/null 2>&1 || true
docker network rm "$baseline_net" "$protected_net" >/dev/null 2>&1 || true

prepare_payload
run_baseline
run_protected

copy_artifacts "$protected_zk_name" "$protected_dir/zookeeper"
copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" "$protected_zk_name" >/dev/null 2>&1 || true
docker network rm "$protected_net" >/dev/null 2>&1 || true

echo "vulhub Dubbo CVE-2019-17564 Java8 acceptance passed"
