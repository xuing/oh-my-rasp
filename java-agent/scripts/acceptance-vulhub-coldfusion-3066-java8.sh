#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_COLDFUSION_3066_IMAGE:-vulhub/coldfusion:11u3}"
baseline_name="${OHMYRASP_VULHUB_COLDFUSION_3066_BASELINE_NAME:-ohmyrasp-coldfusion3066-baseline}"
protected_name="${OHMYRASP_VULHUB_COLDFUSION_3066_PROTECTED_NAME:-ohmyrasp-coldfusion3066-protected}"
baseline_port="${OHMYRASP_VULHUB_COLDFUSION_3066_BASELINE_PORT:-19611}"
protected_port="${OHMYRASP_VULHUB_COLDFUSION_3066_PROTECTED_PORT:-19612}"
marker="${OHMYRASP_VULHUB_COLDFUSION_3066_MARKER:-/tmp/ohmyrasp-coldfusion-3066-success}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
maven_jdk8_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3.8.8-eclipse-temurin-8}"
ysoserial_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
coldfusionpwn_dir="${OHMYRASP_COLDFUSIONPWN_DIR:-/tmp/ohmyrasp-ColdFusionPwn}"
baseline_dir="logs/vulhub-coldfusion-11u3-3066-java8-baseline"
protected_dir="logs/vulhub-coldfusion-11u3-3066-java8-protected"
payload_dir="logs/vulhub-coldfusion-11u3-3066-java8-payload"
protected_log="${protected_dir}/events.jsonl"
payload_file="${payload_dir}/coldfusion-3066.amf"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker exec "$name" sh -lc \
      'tail -n 180 /opt/coldfusion11/cfusion/logs/coldfusion-out.log 2>/dev/null || true; echo "---"; tail -n 180 /opt/coldfusion11/cfusion/logs/exception.log 2>/dev/null || true' \
      > "${dir}/coldfusion-logs.txt" 2>&1 || true
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
  status="$(curl --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

prepare_ysoserial() {
  mkdir -p "$ysoserial_dir"
  if [[ -s "${ysoserial_dir}/ysoserial.jar" ]]; then
    return
  fi
  rm -rf "${ysoserial_dir}/src"
  docker run --rm -v "${ysoserial_dir}:/work" -w /work "$maven_jdk8_image" \
    bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
}

prepare_coldfusionpwn() {
  prepare_ysoserial
  mkdir -p "$coldfusionpwn_dir"
  if [[ -s "${coldfusionpwn_dir}/ColdFusionPwn-0.0.1-SNAPSHOT-all.jar" ]]; then
    return
  fi
  rm -rf "${coldfusionpwn_dir}/src"
  git clone --depth 1 https://github.com/codewhitesec/ColdFusionPwn.git "${coldfusionpwn_dir}/src"
  docker run --rm \
    -v "${coldfusionpwn_dir}/src:/workspace" \
    -v "${ysoserial_dir}/ysoserial.jar:/tmp/ysoserial.jar:ro" \
    -w /workspace \
    "$maven_jdk8_image" \
    mvn -q -Dysoserial=/tmp/ysoserial.jar package
  cp "${coldfusionpwn_dir}/src/target/ColdFusionPwn-0.0.1-SNAPSHOT-all.jar" \
    "${coldfusionpwn_dir}/ColdFusionPwn-0.0.1-SNAPSHOT-all.jar"
}

generate_payload() {
  mkdir -p "$payload_dir"
  prepare_coldfusionpwn
  docker run --rm \
    -v "${coldfusionpwn_dir}/ColdFusionPwn-0.0.1-SNAPSHOT-all.jar:/tool/ColdFusionPwn.jar:ro" \
    -v "${ysoserial_dir}/ysoserial.jar:/tool/ysoserial.jar:ro" \
    -v "$(pwd)/${payload_dir}:/payload" \
    -w /payload \
    eclipse-temurin:8-jdk \
    sh -lc "java -cp /tool/ColdFusionPwn.jar:/tool/ysoserial.jar com.codewhitesec.coldfusionpwn.ColdFusionPwner -e CommonsBeanutils1 'touch ${marker}' coldfusion-3066.amf && test -s coldfusion-3066.amf"
}

verify_image_java8() {
  docker run --rm "$image" sh -lc '/opt/coldfusion11/jre/bin/java -version' \
    > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'version "1.8.0_25"' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "ColdFusion CVE-2017-3066 image did not report Java 8u25" >&2
    exit 1
  fi
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8500" \
    "$image" >/dev/null
}

start_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8500" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    --entrypoint sh \
    "$image" \
    -lc 'sed -i "s#^java.args=#java.args=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true #" /opt/coldfusion11/cfusion/bin/jvm.config && /opt/coldfusion11/cfusion/bin/coldfusion start && exec tail -F /opt/coldfusion11/cfusion/logs/coldfusion-out.log' \
    >/dev/null
}

wait_for_coldfusion() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local require_startup="${4:-false}"
  local status startup
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/ready-${attempt}.html" \
      "http://127.0.0.1:${port}/CFIDE/administrator/index.cfm")"
    startup="yes"
    if [[ "$require_startup" == "true" ]]; then
      startup="no"
      grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log" && startup="yes"
    fi
    printf 'ready_attempt=%s status=%s startup=%s\n' "$attempt" "$status" "$startup" \
      >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]] && [[ "$startup" == "yes" ]]; then
      cp "${dir}/ready-${attempt}.html" "${dir}/administrator-index.html"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "ColdFusion container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "ColdFusion did not become ready on ${port}" >&2
  exit 1
}

send_amf_payload() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -H 'Content-Type: application/x-amf' \
    --data-binary "@${payload_file}" \
    "http://127.0.0.1:${port}/flex2gateway/amf"
}

assert_protected_startup_quiet() {
  if ! grep -Fq '"deserialization_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 deserialization hook startup marker in protected ColdFusion" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected ColdFusion produced a detection before AMF exploit traffic" >&2
    exit 1
  fi
}

command_block_count() {
  grep -Ec '"hook":"Runtime.exec\(String\)".*"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_command_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(command_block_count)"
    if (( count > previous )); then
      printf 'command_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_command_execution_exploit_primitive block event for ColdFusion CVE-2017-3066" >&2
  exit 1
}

run_baseline() {
  start_baseline
  wait_for_coldfusion "$baseline_name" "$baseline_port" "$baseline_dir"
  docker exec "$baseline_name" sh -lc "rm -f '${marker}'" >/dev/null

  local status
  status="$(send_amf_payload "$baseline_port" "${baseline_dir}/amf.response")"
  printf 'baseline_amf_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if ! docker exec "$baseline_name" test -f "$marker"; then
    docker logs "$baseline_name" >&2 || true
    echo "baseline ColdFusion CVE-2017-3066 did not create ${marker}" >&2
    exit 1
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  start_protected
  wait_for_coldfusion "$protected_name" "$protected_port" "$protected_dir" true
  assert_protected_startup_quiet
  docker exec "$protected_name" sh -lc "rm -f '${marker}'" >/dev/null

  local previous_count status
  previous_count="$(command_block_count)"
  status="$(send_amf_payload "$protected_port" "${protected_dir}/amf.response")"
  printf 'protected_amf_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_command_block "$previous_count"
  if docker exec "$protected_name" test -f "$marker"; then
    docker exec "$protected_name" ls -l "$marker" >&2 || true
    echo "protected ColdFusion CVE-2017-3066 marker was created despite block" >&2
    exit 1
  fi
  if ! grep -Fq 'Java deserialization reached a Java 8 process sink' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "ColdFusion CVE-2017-3066 block event did not identify the deserialization process stack" >&2
    exit 1
  fi
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

generate_payload
verify_image_java8
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f -v "$protected_name" >/dev/null 2>&1 || true

echo "vulhub ColdFusion 11u3 CVE-2017-3066 Java8 acceptance passed"
