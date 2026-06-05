#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_JIMUREPORT_IMAGE:-vulhub/jimureport:1.6.0}"
mysql_image="${OHMYRASP_VULHUB_JIMUREPORT_MYSQL_IMAGE:-mysql:5.7}"
network="${OHMYRASP_VULHUB_JIMUREPORT_NETWORK:-ohmyrasp-vulhub-jimureport4450}"
baseline_db="${OHMYRASP_VULHUB_JIMUREPORT_BASELINE_DB_NAME:-ohmyrasp-vulhub-jimureport4450-db-baseline}"
protected_db="${OHMYRASP_VULHUB_JIMUREPORT_PROTECTED_DB_NAME:-ohmyrasp-vulhub-jimureport4450-db-protected}"
baseline_name="${OHMYRASP_VULHUB_JIMUREPORT_BASELINE_NAME:-ohmyrasp-vulhub-jimureport4450-baseline}"
protected_name="${OHMYRASP_VULHUB_JIMUREPORT_PROTECTED_NAME:-ohmyrasp-vulhub-jimureport4450-protected}"
baseline_port="${OHMYRASP_VULHUB_JIMUREPORT_BASELINE_PORT:-18620}"
protected_port="${OHMYRASP_VULHUB_JIMUREPORT_PROTECTED_PORT:-18621}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-jimureport-1.6.0-java17-baseline"
protected_dir="logs/vulhub-jimureport-1.6.0-java17-protected"
protected_log="${protected_dir}/events.jsonl"
payload='{"sql":"select '\''result:<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"cat /etc/passwd\")}'\''"}'

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker logs "$baseline_db" > "${baseline_dir}/mysql.log" 2>&1 || true
  docker logs "$protected_db" > "${protected_dir}/mysql.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" "$baseline_db" "$protected_db" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" "$baseline_db" "$protected_db" >/dev/null 2>&1 || true
docker network rm "$network" >/dev/null 2>&1 || true
docker network create "$network" >/dev/null

docker run -d --name "$baseline_db" --network "$network" \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=jimureport \
  "$mysql_image" >/dev/null
docker run -d --name "$protected_db" --network "$network" \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=jimureport \
  "$mysql_image" >/dev/null

docker run -d --name "$baseline_name" --network "$network" -p "${baseline_port}:8085" \
  -e MYSQL_HOST="$baseline_db" \
  -e MYSQL_PORT=3306 \
  -e MYSQL_DB=jimureport \
  -e MYSQL_USER=root \
  -e MYSQL_PASSWORD=root \
  "$image" >/dev/null

docker run -d --name "$protected_name" --network "$network" -p "${protected_port}:8085" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e MYSQL_HOST="$protected_db" \
  -e MYSQL_PORT=3306 \
  -e MYSQL_DB=jimureport \
  -e MYSQL_USER=root \
  -e MYSQL_PASSWORD=root \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
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
  echo "${name} did not expose JimuReport at ${port}" >&2
  exit 1
}

post_ssti() {
  local port="$1"
  local output="$2"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "http://127.0.0.1:${port}/jmreport/queryFieldBySql" || true
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17 startup event in JimuReport protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "JimuReport protected startup produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(post_ssti "$baseline_port" "${baseline_dir}/ssti.response")"
if [[ "$baseline_status" != "200" ]] || ! grep -q 'root:.*:0:0:' "${baseline_dir}/ssti.response"; then
  cat "${baseline_dir}/ssti.response" >&2 || true
  echo "baseline JimuReport did not execute the FreeMarker SSTI command" >&2
  exit 1
fi

protected_status="$(post_ssti "$protected_port" "${protected_dir}/ssti.response")"
if [[ "$protected_status" != "200" ]]; then
  cat "${protected_dir}/ssti.response" >&2 || true
  echo "protected JimuReport returned unexpected HTTP status ${protected_status}" >&2
  exit 1
fi
if grep -q 'root:.*:0:0:' "${protected_dir}/ssti.response"; then
  cat "${protected_dir}/ssti.response" >&2
  echo "protected JimuReport leaked /etc/passwd despite Java17 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java17_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_command_execution_exploit_primitive block event for JimuReport CVE-2023-4450" >&2
  exit 1
fi

echo "vulhub JimuReport 1.6.0 CVE-2023-4450 Java17 acceptance passed"
