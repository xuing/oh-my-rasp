#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_STRUTS2_S2059_IMAGE:-vulhub/struts2:2.5.16}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2059_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2059-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2059_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2059-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2059_BASELINE_PORT:-18534}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2059_PROTECTED_PORT:-18535}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-059-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-059-java8-protected"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-s2059-success"

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
      "http://127.0.0.1:${port}/?id=1" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 S2-059 root at ${port}" >&2
  exit 1
}

post_payloads() {
  local port="$1"
  local output_dir="$2"
  python3 - "$port" "$output_dir" "$marker" <<'PY'
import sys
import requests

port, output_dir, marker = sys.argv[1:]
prep = "%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))}"
run = "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('touch " + marker + "'))}"

def post(payload, label):
    response = requests.post(f"http://127.0.0.1:{port}/", data={"id": payload}, timeout=20)
    with open(f"{output_dir}/{label}.response", "wb") as handle:
        handle.write(response.content)
    with open(f"{output_dir}/{label}.status", "w", encoding="utf-8") as handle:
        handle.write(str(response.status_code))
    if response.status_code != 200:
        raise SystemExit(f"{label} on {port} returned {response.status_code}")

post(prep, "step1")
post(run, "step2")
PY
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

docker exec "$baseline_name" rm -f "$marker" >/dev/null
docker exec "$protected_name" rm -f "$marker" >/dev/null

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Struts2 S2-059 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-059 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

post_payloads "$baseline_port" "$baseline_dir"
if ! docker exec "$baseline_name" test -e "$marker"; then
  sed -n '1,160p' "${baseline_dir}/step2.response" >&2 || true
  echo "baseline Struts2 S2-059 did not create ${marker}" >&2
  exit 1
fi

post_payloads "$protected_port" "$protected_dir"
if docker exec "$protected_name" test -e "$marker"; then
  echo "protected Struts2 S2-059 created ${marker} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-059" >&2
  exit 1
fi

echo "vulhub Struts2 S2-059 Java8 acceptance passed"
