#!/usr/bin/env bash
set -euo pipefail

image="${OHMYRASP_VULHUB_NEXUS_4956_IMAGE:-vulhub/nexus:3.68.0}"
baseline_name="${OHMYRASP_VULHUB_NEXUS_4956_BASELINE_NAME:-ohmyrasp-vulhub-nexus4956-baseline}"
protected_name="${OHMYRASP_VULHUB_NEXUS_4956_PROTECTED_NAME:-ohmyrasp-vulhub-nexus4956-protected}"
baseline_port="${OHMYRASP_VULHUB_NEXUS_4956_BASELINE_PORT:-18687}"
protected_port="${OHMYRASP_VULHUB_NEXUS_4956_PROTECTED_PORT:-18688}"
admin_password_file="${OHMYRASP_VULHUB_NEXUS_4956_ADMIN_PASSWORD_FILE:-/tmp/vulhub-ohmyrasp-20260603/nexus/CVE-2024-4956/admin.password}"
traversal_path="/%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
agent_root="${repo_root}/java-agent"
agent_jar="${agent_root}/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
work_dir="${OHMYRASP_VULHUB_NEXUS_4956_WORK_DIR:-/tmp/ohmyrasp-nexus4956}"
baseline_response="${work_dir}/baseline-passwd.txt"
protected_response="${work_dir}/protected-passwd.txt"
protected_home="${work_dir}/protected-home.html"
protected_logs="${work_dir}/protected-logs"
protected_log="${protected_logs}/events.jsonl"

cleanup() {
  docker rm -f "${baseline_name}" "${protected_name}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

wait_for_http() {
  local port="$1"
  local name="$2"
  for attempt in $(seq 1 180); do
    local status
    status="$(curl -fsS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "${status}" == "200" || "${status}" == "302" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "Nexus ${name} did not become ready" >&2
  docker logs --tail 200 "${name}" >&2 || true
  return 1
}

read_home() {
  local port="$1"
  local response_file="$2"
  local status
  status="$(curl -sS -o "${response_file}" -w '%{http_code}' "http://127.0.0.1:${port}/")"
  if [[ "${status}" != "200" && "${status}" != "302" ]]; then
    echo "Nexus home read failed on port ${port}; status=${status}" >&2
    cat "${response_file}" >&2 || true
    return 1
  fi
}

send_traversal() {
  local port="$1"
  local response_file="$2"
  curl -sS \
    --path-as-is \
    -o "${response_file}" \
    -w '%{http_code}' \
    "http://127.0.0.1:${port}${traversal_path}"
}

sensitive_read_block_count() {
  grep -Ec '"algorithm":"java8_file_sensitive_read".*"action":"block"' "${protected_log}" 2>/dev/null || true
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
  -e "INSTALL4J_ADD_VM_PARAMS=-Xms2703m -Xmx2703m -XX:MaxDirectMemorySize=2703m -Djava.util.prefs.userRoot=/nexus-data/javaprefs -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "${image}" >/dev/null

wait_for_http "${baseline_port}" "${baseline_name}"
wait_for_http "${protected_port}" "${protected_name}"

if ! grep -q '"file_hook":"installed"' "${protected_log}"; then
  echo "protected Nexus Java8 agent did not report installed file hook" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

read_home "${protected_port}" "${protected_home}"

if grep -q '"event":"ohmyrasp-detection"' "${protected_log}"; then
  echo "protected Nexus logged a detection before the traversal request" >&2
  cat "${protected_log}" >&2
  exit 1
fi

baseline_status="$(send_traversal "${baseline_port}" "${baseline_response}")"
if [[ "${baseline_status}" != "200" ]] || ! grep -q '^root:x:0:0:' "${baseline_response}"; then
  echo "baseline Nexus CVE-2024-4956 traversal did not disclose /etc/passwd; status=${baseline_status}" >&2
  cat "${baseline_response}" >&2 || true
  docker logs --tail 120 "${baseline_name}" >&2 || true
  exit 1
fi

before_count="$(sensitive_read_block_count)"
protected_status="$(send_traversal "${protected_port}" "${protected_response}")"
for _ in $(seq 1 20); do
  after_count="$(sensitive_read_block_count)"
  if [[ "${after_count}" -gt "${before_count}" ]]; then
    break
  fi
  sleep 1
done

after_count="$(sensitive_read_block_count)"
if [[ "${after_count}" -le "${before_count}" ]]; then
  echo "missing java8_file_sensitive_read block event for Nexus CVE-2024-4956; status=${protected_status}" >&2
  cat "${protected_log}" >&2 || true
  cat "${protected_response}" >&2 || true
  exit 1
fi

if grep -q '^root:x:0:0:' "${protected_response}"; then
  echo "protected Nexus CVE-2024-4956 traversal disclosed /etc/passwd despite RASP; status=${protected_status}" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

echo "vulhub Nexus CVE-2024-4956 Java8 acceptance passed"
