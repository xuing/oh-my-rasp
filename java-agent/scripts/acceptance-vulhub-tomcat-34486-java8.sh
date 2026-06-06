#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

vulhub_dir="${OHMYRASP_VULHUB_TOMCAT_34486_DIR:-/tmp/vulhub-ohmyrasp-20260603/tomcat/CVE-2026-34486}"
poc_py="${OHMYRASP_VULHUB_TOMCAT_34486_POC:-${vulhub_dir}/poc.py}"
image="${OHMYRASP_VULHUB_TOMCAT_34486_IMAGE:-vulhub/tomcat:9.0.116}"
baseline_name="${OHMYRASP_VULHUB_TOMCAT_34486_BASELINE_NAME:-ohmyrasp-tomcat34486-baseline}"
protected_name="${OHMYRASP_VULHUB_TOMCAT_34486_PROTECTED_NAME:-ohmyrasp-tomcat34486-protected}"
baseline_http_port="${OHMYRASP_VULHUB_TOMCAT_34486_BASELINE_HTTP_PORT:-19080}"
baseline_tribes_port="${OHMYRASP_VULHUB_TOMCAT_34486_BASELINE_TRIBES_PORT:-19400}"
protected_http_port="${OHMYRASP_VULHUB_TOMCAT_34486_PROTECTED_HTTP_PORT:-19081}"
protected_tribes_port="${OHMYRASP_VULHUB_TOMCAT_34486_PROTECTED_TRIBES_PORT:-19401}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
ysoserial_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
maven_jdk8_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3.8.1-jdk-8}"
baseline_dir="logs/vulhub-tomcat-9.0.116-34486-java8-baseline"
protected_dir="logs/vulhub-tomcat-9.0.116-34486-java8-protected"
payload_dir="logs/vulhub-tomcat-9.0.116-34486-java8-payload"
protected_log="${protected_dir}/events.jsonl"
payload_ser="${payload_dir}/payload.ser"
marker="/tmp/ohmyrasp-tomcat-34486-success"

prepare_ysoserial() {
  mkdir -p "$ysoserial_dir"
  if [[ ! -s "${ysoserial_dir}/ysoserial.jar" ]]; then
    rm -rf "${ysoserial_dir}/src"
    docker run --rm -v "${ysoserial_dir}:/work" -w /work "$maven_jdk8_image" \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
}

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker exec "$name" sh -c "ls -l ${marker} 2>/dev/null || true" \
      > "${dir}/marker.txt" 2>/dev/null || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 30 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

verify_inputs() {
  if [[ ! -f "$poc_py" ]]; then
    echo "Tomcat CVE-2026-34486 poc.py is missing: ${poc_py}" >&2
    exit 1
  fi
  docker run --rm --entrypoint java "$image" -version > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Eq 'version "1\.8\.' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "Tomcat CVE-2026-34486 image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

write_payload() {
  docker run --rm \
    -e MARKER="$marker" \
    -v "${ysoserial_dir}:/ysoserial:ro" \
    -v "$(pwd)/${payload_dir}:/payload" \
    -w /payload \
    --entrypoint sh \
    "$image" \
    -c 'java -jar /ysoserial/ysoserial.jar CommonsCollections6 "touch ${MARKER}" > payload.ser && test -s payload.ser && ls -l payload.ser' \
    > "${payload_dir}/payload-generation.txt"
  if [[ ! -s "$payload_ser" ]]; then
    cat "${payload_dir}/payload-generation.txt" >&2 || true
    echo "Tomcat CVE-2026-34486 serialized payload was not generated" >&2
    exit 1
  fi
}

wait_for_tomcat() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "http://127.0.0.1:${port}/")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] && grep -Fq "Apache Tomcat" "${dir}/ready-${attempt}.response"; then
      cp "${dir}/ready-${attempt}.response" "${dir}/home.response"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "Tomcat CVE-2026-34486 container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Tomcat CVE-2026-34486 did not expose HTTP at ${port}" >&2
  exit 1
}

send_payload() {
  local port="$1"
  local output="$2"
  python3 "$poc_py" -t 127.0.0.1 -p "$port" -f "$payload_ser" --timeout 5 \
    > "$output" 2>&1
}

wait_for_marker() {
  local name="$1"
  for attempt in $(seq 1 20); do
    if docker exec "$name" test -f "$marker"; then
      printf 'marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "baseline Tomcat CVE-2026-34486 did not create ${marker}" >&2
  exit 1
}

wait_for_agent_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event for Tomcat CVE-2026-34486 protected container" >&2
  exit 1
}

block_count() {
  grep -Ec '"hook":"ObjectInputStream.resolveClass".*"algorithm":"java8_deserialization_gadget_class".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_deserialization_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(block_count)"
    if (( count > previous )); then
      printf 'deserialization_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_deserialization_gadget_class block event for Tomcat CVE-2026-34486" >&2
  exit 1
}

assert_protected_startup_quiet() {
  if ! grep -Fq '"deserialization_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 deserialization hook startup marker in protected Tomcat CVE-2026-34486 container" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Tomcat CVE-2026-34486 produced a detection before Tribes payload traffic" >&2
    exit 1
  fi
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_http_port}:8080" \
    -p "${baseline_tribes_port}:4000" \
    "$image" >/dev/null

  wait_for_tomcat "$baseline_name" "$baseline_http_port" "$baseline_dir"
  send_payload "$baseline_tribes_port" "${baseline_dir}/poc.out"
  wait_for_marker "$baseline_name"
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_http_port}:8080" \
    -p "${protected_tribes_port}:4000" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_agent_startup
  wait_for_tomcat "$protected_name" "$protected_http_port" "$protected_dir"
  assert_protected_startup_quiet

  docker exec "$protected_name" rm -f "$marker"
  previous_count="$(block_count)"
  send_payload "$protected_tribes_port" "${protected_dir}/poc.out"
  wait_for_deserialization_block "$previous_count"
  if ! grep -Fq '"class":"org.apache.commons.collections.functors.ChainedTransformer"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "Tomcat CVE-2026-34486 block event did not record the CommonsCollections6 ChainedTransformer gadget class" >&2
    exit 1
  fi
  sleep 2
  if docker exec "$protected_name" test -f "$marker"; then
    cat "$protected_log" >&2 || true
    echo "protected Tomcat CVE-2026-34486 still created ${marker}" >&2
    exit 1
  fi
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

verify_inputs
prepare_ysoserial
write_payload
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f -v "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Tomcat 9.0.116 CVE-2026-34486 Java8 acceptance passed"
