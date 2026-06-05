#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_GEOSERVER_IMAGE:-vulhub/geoserver:2.23.2}"
baseline_name="${OHMYRASP_VULHUB_GEOSERVER_BASELINE_NAME:-ohmyrasp-vulhub-geoserver24236401-baseline}"
protected_name="${OHMYRASP_VULHUB_GEOSERVER_PROTECTED_NAME:-ohmyrasp-vulhub-geoserver24236401-protected}"
baseline_port="${OHMYRASP_VULHUB_GEOSERVER_BASELINE_PORT:-18280}"
protected_port="${OHMYRASP_VULHUB_GEOSERVER_PROTECTED_PORT:-18281}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-geoserver-2.23.2-java17-baseline"
protected_dir="logs/vulhub-geoserver-2.23.2-java17-protected"
protected_log="${protected_dir}/events.jsonl"
payload_path="/geoserver/wfs?service=WFS&version=2.0.0&request=GetPropertyValue&typeNames=sf:archsites&valueReference=exec(java.lang.Runtime.getRuntime(),'cat%20/etc/passwd')"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
  -e JAVA_OPTS= \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_OPTS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 240); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/geoserver/web/" || true)"
    if [[ "$status" =~ ^(200|302)$ ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose GeoServer web UI at ${port}" >&2
  exit 1
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17 startup event in GeoServer protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "GeoServer protected startup produced a detection before the WFS exploit request" >&2
  exit 1
fi

baseline_status="$(
  curl -sS -o "${baseline_dir}/wfs-valuereference.txt" -w "%{http_code}" \
    "http://127.0.0.1:${baseline_port}${payload_path}" || true
)"
if [[ "$baseline_status" != "400" ]] \
    || ! grep -q 'ProcessImpl cannot be cast' "${baseline_dir}/wfs-valuereference.txt"; then
  cat "${baseline_dir}/wfs-valuereference.txt" >&2 || true
  echo "baseline GeoServer CVE-2024-36401 request did not reach Runtime.exec" >&2
  exit 1
fi

protected_status="$(
  curl -sS -o "${protected_dir}/wfs-valuereference.txt" -w "%{http_code}" \
    "http://127.0.0.1:${protected_port}${payload_path}" || true
)"
if [[ "$protected_status" != "500" ]]; then
  cat "${protected_dir}/wfs-valuereference.txt" >&2 || true
  echo "protected GeoServer CVE-2024-36401 request returned unexpected HTTP ${protected_status}" >&2
  exit 1
fi
if grep -q 'ProcessImpl cannot be cast' "${protected_dir}/wfs-valuereference.txt"; then
  cat "${protected_dir}/wfs-valuereference.txt" >&2
  echo "protected GeoServer CVE-2024-36401 request still reached Runtime.exec" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java17_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_command_execution_exploit_primitive block event for GeoServer CVE-2024-36401" >&2
  exit 1
fi
if grep -q '"algorithm":"java17_xxe_external_entity_protocol"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "GeoServer runtime DTDs were incorrectly reported as XXE" >&2
  exit 1
fi

echo "vulhub GeoServer 2.23.2 CVE-2024-36401 Java17 acceptance passed"
