#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

baseline_name="${OHMYRASP_VULHUB_METABASE_41277_BASELINE_NAME:-ohmyrasp-vulhub-metabase-41277-baseline}"
protected_name="${OHMYRASP_VULHUB_METABASE_41277_PROTECTED_NAME:-ohmyrasp-vulhub-metabase-41277-protected}"
baseline_port="${OHMYRASP_VULHUB_METABASE_41277_BASELINE_PORT:-18798}"
protected_port="${OHMYRASP_VULHUB_METABASE_41277_PROTECTED_PORT:-18799}"
image="${OHMYRASP_VULHUB_METABASE_41277_IMAGE:-vulhub/metabase:0.40.4}"
baseline_dir="logs/vulhub-metabase-2021-41277-java11-baseline"
protected_dir="logs/vulhub-metabase-2021-41277-java11-protected"
protected_log="${protected_dir}/events.jsonl"
geojson_path="/api/geojson?url=file:////etc/passwd"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 300); do
    status="$(curl --max-time 2 -sS -o "/tmp/${name}.health" -w "%{http_code}" \
      "http://127.0.0.1:${port}/api/health" 2>/dev/null || true)"
    if [[ "$status" == "200" || "$status" == "204" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Metabase health at ${port}" >&2
  exit 1
}

send_geojson_file_read() {
  local port="$1"
  local output="$2"
  curl --max-time 20 -sS -i -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}${geojson_path}" || true
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 11 startup event in protected Metabase container" >&2
    exit 1
  fi
  if ! grep -q '"file_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 11 file hook startup marker in protected Metabase container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Metabase container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
chmod 755 "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:3000" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:3000" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true" \
  "$image" >/dev/null

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_status="$(send_geojson_file_read "$baseline_port" "${baseline_dir}/geojson.response")"
if [[ "$baseline_status" != "200" ]]; then
  cat "${baseline_dir}/geojson.response" >&2 || true
  echo "baseline Metabase GeoJSON file read returned unexpected status ${baseline_status}" >&2
  exit 1
fi
if ! grep -q 'root:x:0:0:' "${baseline_dir}/geojson.response" ||
  ! grep -q 'daemon:x:' "${baseline_dir}/geojson.response"; then
  cat "${baseline_dir}/geojson.response" >&2 || true
  echo "baseline Metabase GeoJSON file read did not disclose /etc/passwd" >&2
  exit 1
fi

protected_status="$(send_geojson_file_read "$protected_port" "${protected_dir}/geojson.response")"
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/geojson.response" >&2 || true
  echo "protected Metabase GeoJSON request did not reach the HTTP endpoint" >&2
  exit 1
fi
if grep -q 'root:x:0:0:' "${protected_dir}/geojson.response" ||
  grep -q 'daemon:x:' "${protected_dir}/geojson.response"; then
  cat "${protected_dir}/geojson.response" >&2 || true
  echo "protected Metabase disclosed /etc/passwd despite Java11 RASP" >&2
  exit 1
fi
if ! grep -q '"hook":"FileInputStream.open".*"algorithm":"java11_file_sensitive_read".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java11_file_sensitive_read block event for Metabase CVE-2021-41277" >&2
  exit 1
fi
if ! grep -q '"path":"/etc/passwd"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing /etc/passwd path evidence for protected Metabase CVE-2021-41277" >&2
  exit 1
fi

echo "vulhub Metabase CVE-2021-41277 Java11 acceptance passed"
