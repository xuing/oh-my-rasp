#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_DATAEASE_56511_IMAGE:-vulhub/dataease:2.10.3}"
mysql_image="${OHMYRASP_VULHUB_DATAEASE_56511_MYSQL_IMAGE:-mysql:8.4}"
network="${OHMYRASP_VULHUB_DATAEASE_56511_NETWORK:-ohmyrasp-vulhub-dataease56511}"
baseline_db="${OHMYRASP_VULHUB_DATAEASE_56511_BASELINE_DB_NAME:-ohmyrasp-vulhub-dataease56511-db-baseline}"
protected_db="${OHMYRASP_VULHUB_DATAEASE_56511_PROTECTED_DB_NAME:-ohmyrasp-vulhub-dataease56511-db-protected}"
baseline_name="${OHMYRASP_VULHUB_DATAEASE_56511_BASELINE_NAME:-ohmyrasp-vulhub-dataease56511-baseline}"
protected_name="${OHMYRASP_VULHUB_DATAEASE_56511_PROTECTED_NAME:-ohmyrasp-vulhub-dataease56511-protected}"
baseline_port="${OHMYRASP_VULHUB_DATAEASE_56511_BASELINE_PORT:-18722}"
protected_port="${OHMYRASP_VULHUB_DATAEASE_56511_PROTECTED_PORT:-18723}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-dataease-2.10.3-cve-2024-56511-java21-baseline"
protected_dir="logs/vulhub-dataease-2.10.3-cve-2024-56511-java21-protected"
protected_log="${protected_dir}/events.jsonl"
direct_path="/dataease/de2api/datasource/types"
bypass_path="/geo/../dataease/de2api/datasource/types"

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
  -e MYSQL_DATABASE=dataease \
  "$mysql_image" >/dev/null
docker run -d --name "$protected_db" --network "$network" \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=dataease \
  "$mysql_image" >/dev/null

docker run -d --name "$baseline_name" --network "$network" -p "${baseline_port}:8100" \
  -e MYSQL_HOST="$baseline_db" \
  -e MYSQL_PORT=3306 \
  -e MYSQL_DB=dataease \
  -e MYSQL_USER=root \
  -e MYSQL_PASSWORD=root \
  "$image" >/dev/null

docker run -d --name "$protected_name" --network "$network" -p "${protected_port}:8100" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e MYSQL_HOST="$protected_db" \
  -e MYSQL_PORT=3306 \
  -e MYSQL_DB=dataease \
  -e MYSQL_USER=root \
  -e MYSQL_PASSWORD=root \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
  "$image" >/dev/null

wait_for_dataease() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 420); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/dataease" 2>/dev/null || true)"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose DataEase /dataease on ${port}" >&2
  exit 1
}

get_path() {
  local port="$1"
  local path="$2"
  local output="$3"
  curl --path-as-is -sS -D "${output}.headers" -o "${output}.body" -w "%{http_code}" \
    "http://127.0.0.1:${port}${path}" || true
}

wait_for_dataease "$baseline_name" "$baseline_port"
wait_for_dataease "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17-compatible startup event in DataEase protected container" >&2
  exit 1
fi
if ! grep -Eq '"java_version":"21\.' "$protected_log"; then
  cat "$protected_log" >&2
  echo "DataEase protected container did not report a Java 21 runtime" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "DataEase protected startup produced a detection before the whitelist traversal request" >&2
  exit 1
fi

baseline_direct_status="$(get_path "$baseline_port" "$direct_path" "${baseline_dir}/direct")"
if [[ "$baseline_direct_status" != "500" ]]; then
  cat "${baseline_dir}/direct.body" >&2 || true
  echo "baseline DataEase direct datasource types request returned ${baseline_direct_status}, expected 500" >&2
  exit 1
fi

baseline_bypass_status="$(get_path "$baseline_port" "$bypass_path" "${baseline_dir}/bypass")"
if [[ "$baseline_bypass_status" != "200" ]]; then
  cat "${baseline_dir}/bypass.body" >&2 || true
  echo "baseline DataEase whitelist traversal returned ${baseline_bypass_status}, expected 200" >&2
  exit 1
fi
if ! grep -q '"code":0' "${baseline_dir}/bypass.body" || ! grep -q '"h2"' "${baseline_dir}/bypass.body"; then
  cat "${baseline_dir}/bypass.body" >&2 || true
  echo "baseline DataEase whitelist traversal did not return the datasource type list" >&2
  exit 1
fi

protected_direct_status="$(get_path "$protected_port" "$direct_path" "${protected_dir}/direct")"
if [[ "$protected_direct_status" != "500" ]]; then
  cat "${protected_dir}/direct.body" >&2 || true
  echo "protected DataEase direct datasource types request returned ${protected_direct_status}, expected 500" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected DataEase direct datasource types request produced a detection" >&2
  exit 1
fi

protected_bypass_status="$(get_path "$protected_port" "$bypass_path" "${protected_dir}/bypass")"
if [[ "$protected_bypass_status" == "200" ]] && grep -q '"code":0' "${protected_dir}/bypass.body"; then
  cat "${protected_dir}/bypass.body" >&2 || true
  echo "protected DataEase returned the datasource type list despite Java17-compatible RASP" >&2
  exit 1
fi
if ! grep -q '"hook":"HttpServlet.service".*"algorithm":"java17_request_path_confusion".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_request_path_confusion block event for DataEase CVE-2024-56511" >&2
  exit 1
fi
if ! grep -Fq '/geo/../dataease/de2api/datasource/types' "$protected_log"; then
  cat "$protected_log" >&2
  echo "DataEase CVE-2024-56511 block event did not include the whitelist traversal path" >&2
  exit 1
fi

echo "vulhub DataEase 2.10.3 CVE-2024-56511 Java21 runtime acceptance passed"
