#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_NEO4J_34371_IMAGE:-vulhub/neo4j:3.4.18}"
baseline_name="${OHMYRASP_VULHUB_NEO4J_34371_BASELINE_NAME:-ohmyrasp-vulhub-neo4j34371-baseline}"
protected_name="${OHMYRASP_VULHUB_NEO4J_34371_PROTECTED_NAME:-ohmyrasp-vulhub-neo4j34371-protected}"
vulhub_root="${OHMYRASP_VULHUB_ROOT:-/tmp/vulhub-ohmyrasp-20260603}"
exploit_src="${OHMYRASP_VULHUB_NEO4J_34371_RHINO_SRC:-${vulhub_root}/neo4j/CVE-2021-34371/rhino_gadget}"
exploit_dir="${OHMYRASP_VULHUB_NEO4J_34371_WORKDIR:-/tmp/ohmyrasp-neo4j-rhino}"
maven_jdk8_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3-jdk-8}"
exploit_jar_name="rhino_gadget-1.0-SNAPSHOT-fatjar.jar"
success_file="/tmp/ohmyrasp-neo4j34371-success"
baseline_dir="logs/vulhub-neo4j-2021-34371-java8-baseline"
protected_dir="logs/vulhub-neo4j-2021-34371-java8-protected"
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

ensure_host_ports_available() {
  local port
  for port in 7474 7687 1337 34444; do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
      echo "host port ${port} is already in use; Neo4j CVE-2021-34371 acceptance uses host networking for RMI" >&2
      exit 1
    fi
  done
}

prepare_exploit() {
  if [[ ! -d "${exploit_src}/src/main/java" ]]; then
    echo "missing Vulhub Neo4j rhino_gadget source at ${exploit_src}" >&2
    exit 1
  fi

  mkdir -p "$exploit_dir"
  docker run --rm -v "${exploit_dir}:/work" -w /work "$maven_jdk8_image" \
    bash -lc 'rm -rf /work/* /work/.[!.]* /work/..?* 2>/dev/null || true; chmod 777 /work'
  cp -R "${exploit_src}/." "$exploit_dir"
  docker run --rm -v "${exploit_dir}:/work" -w /work "$maven_jdk8_image" \
    mvn -q -DskipTests package
  if [[ ! -s "${exploit_dir}/target/${exploit_jar_name}" ]]; then
    echo "missing built Neo4j rhino_gadget fat jar at ${exploit_dir}/target/${exploit_jar_name}" >&2
    exit 1
  fi
}

wait_for_neo4j() {
  local name="$1"
  local dir="$2"

  for attempt in $(seq 1 120); do
    if curl -fsS --max-time 1 http://127.0.0.1:7474/ >/dev/null 2>&1 \
      && timeout 1 bash -c "</dev/tcp/127.0.0.1/1337" >/dev/null 2>&1; then
      printf 'neo4j_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose Neo4j HTTP 7474 and shell RMI 1337 on host networking" >&2
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
  docker logs "$protected_name" >&2 || true
  echo "missing Java8 agent startup event for Neo4j CVE-2021-34371" >&2
  exit 1
}

run_rhino_exploit() {
  local dir="$1"
  local output="${dir}/rhino-gadget-exploit.log"
  local status

  set +e
  docker run --rm --network host -v "${exploit_dir}/target:/work:ro" -w /work "$maven_jdk8_image" \
    java -jar "$exploit_jar_name" rmi://127.0.0.1:1337 "touch ${success_file}" \
    > "$output" 2>&1
  status=$?
  set -e
  printf 'exploit_status=%s\n' "$status" >> "${dir}/attempts.log"
}

start_baseline() {
  docker run -d --name "$baseline_name" --network host \
    -e NEO4J_AUTH=neo4j/vulhub \
    -e NEO4J_dbms_jvm_additional="-Djava.rmi.server.hostname=127.0.0.1" \
    "$image" >/dev/null
  wait_for_neo4j "$baseline_name" "$baseline_dir"
}

start_protected() {
  docker run -d --name "$protected_name" --network host \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/tmp/ohmyrasp-logs" \
    -e NEO4J_AUTH=neo4j/vulhub \
    -e NEO4J_dbms_jvm_additional="-javaagent:/tmp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/tmp/ohmyrasp-logs/events.jsonl -Dohmyrasp.java8.block=true -Djava.rmi.server.hostname=127.0.0.1" \
    "$image" >/dev/null
  wait_for_neo4j "$protected_name" "$protected_dir"
  wait_for_protected_startup
}

run_baseline() {
  start_baseline
  docker exec "$baseline_name" rm -f "$success_file"
  run_rhino_exploit "$baseline_dir"

  for attempt in $(seq 1 15); do
    if docker exec "$baseline_name" test -e "$success_file"; then
      printf 'baseline_marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      copy_artifacts "$baseline_name" "$baseline_dir"
      docker rm -f "$baseline_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done

  docker logs "$baseline_name" >&2 || true
  cat "${baseline_dir}/rhino-gadget-exploit.log" >&2 || true
  echo "baseline Neo4j CVE-2021-34371 did not execute the rhino_gadget payload" >&2
  exit 1
}

run_protected() {
  start_protected
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Neo4j container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  run_rhino_exploit "$protected_dir"
  sleep 2

  if docker exec "$protected_name" test -e "$success_file"; then
    echo "protected Neo4j CVE-2021-34371 created ${success_file} despite Java8 RASP" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    docker logs "$protected_name" >&2 || true
    echo "missing java8_deserialization_gadget_class block event for Neo4j CVE-2021-34371" >&2
    exit 1
  fi
  if ! grep -Fq '"class":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "Neo4j CVE-2021-34371 block event did not identify TemplatesImpl gadget class" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
ensure_host_ports_available

prepare_exploit
run_baseline
ensure_host_ports_available
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Neo4j CVE-2021-34371 Java8 acceptance passed"
