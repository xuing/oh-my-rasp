#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

context="${OHMYRASP_VULHUB_STRUTS2_S2008_CONTEXT:-/tmp/vulhub-ohmyrasp-20260603/struts2/s2-008}"
image="${OHMYRASP_VULHUB_STRUTS2_S2008_IMAGE:-ohmyrasp/vulhub-struts2:s2-008}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2008_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2008-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2008_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2008-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2008_BASELINE_PORT:-18564}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2008_PROTECTED_PORT:-18565}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-008-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-008-java8-protected"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-s2008-success"

if [[ ! -f "${context}/Dockerfile" ]]; then
  echo "missing Vulhub Struts2 S2-008 Dockerfile under ${context}" >&2
  exit 1
fi

docker build -t "$image" "$context" >/dev/null

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
      "http://127.0.0.1:${port}/devmode.action" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 S2-008 devmode action at ${port}" >&2
  exit 1
}

get_payload() {
  local port="$1"
  local output="$2"
  python3 - "$port" "$output" "$marker" <<'PY'
import http.client
import sys
import urllib.parse

port = int(sys.argv[1])
output = sys.argv[2]
marker = sys.argv[3]
expression = (
    "("
    '#_memberAccess["allowStaticMethodAccess"]=true,'
    '#foo=new java.lang.Boolean("false"),'
    '#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,'
    f'@java.lang.Runtime@getRuntime().exec("touch {marker}")'
    ")"
)
query = urllib.parse.urlencode({"debug": "command", "expression": expression})
headers = {"User-Agent": "ohmyrasp-s2-008"}
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
try:
    connection.request("GET", f"/devmode.action?{query}", headers=headers)
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

docker exec "$baseline_name" rm -f "$marker" >/dev/null
docker exec "$protected_name" rm -f "$marker" >/dev/null

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Struts2 S2-008 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-008 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(get_payload "$baseline_port" "${baseline_dir}/attack.response")"
if [[ "$baseline_status" != "200" ]] || ! docker exec "$baseline_name" test -e "$marker"; then
  sed -n '1,120p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-008 debug command did not create ${marker}; status=${baseline_status}" >&2
  exit 1
fi
if ! grep -q 'UNIXProcess' "${baseline_dir}/attack.response"; then
  sed -n '1,120p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-008 response did not return the devMode command result" >&2
  exit 1
fi

protected_status="$(get_payload "$protected_port" "${protected_dir}/attack.response")"
if docker exec "$protected_name" test -e "$marker"; then
  echo "protected Struts2 S2-008 created ${marker} despite Java8 RASP; status=${protected_status}" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    echo "vulhub Struts2 S2-008 Java8 acceptance passed"
    exit 0
  fi
  sleep 1
done

cat "$protected_log" >&2
echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-008" >&2
exit 1
