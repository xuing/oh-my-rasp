#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_SOLR12629_RCE_BASELINE_NAME:-ohmyrasp-vulhub-solr12629-rce-baseline}"
protected_name="${OHMYRASP_VULHUB_SOLR12629_RCE_PROTECTED_NAME:-ohmyrasp-vulhub-solr12629-rce-protected}"
baseline_port="${OHMYRASP_VULHUB_SOLR12629_RCE_BASELINE_PORT:-18784}"
protected_port="${OHMYRASP_VULHUB_SOLR12629_RCE_PROTECTED_PORT:-18785}"
image="${OHMYRASP_VULHUB_SOLR12629_RCE_IMAGE:-vulhub/solr:7.0.1}"
marker="/tmp/ohmyrasp-solr12629-success"
baseline_dir="logs/vulhub-solr-2017-12629-rce-java8-baseline"
protected_dir="logs/vulhub-solr-2017-12629-rce-java8-protected"
protected_log="${protected_dir}/events.jsonl"

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
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/solr/admin/cores?indexInfo=false&wt=json" \
      2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q '"demo"' "/tmp/${name}.json"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Solr demo core at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Solr container" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Solr container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Solr container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

add_run_executable_listener() {
  local port="$1"
  local output="$2"
  local body
  body="$(
    printf '{"add-listener":{"event":"postCommit","name":"ohmyrasp-listener","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c","touch %s"]}}' \
      "$marker"
  )"
  curl -sS -i -H 'Content-Type: application/json' --data "$body" \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/solr/demo/config" || true
}

trigger_commit() {
  local port="$1"
  local output="$2"
  curl -sS -i -H 'Content-Type: application/json' \
    --data '[{"id":"ohmyrasp-solr12629"}]' \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/solr/demo/update?commit=true" || true
}

marker_state() {
  local name="$1"
  docker exec "$name" sh -lc "test -f '$marker' && echo present || echo missing" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8983" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8983" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "SOLR_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_config_status="$(add_run_executable_listener "$baseline_port" "${baseline_dir}/config.response")"
protected_config_status="$(add_run_executable_listener "$protected_port" "${protected_dir}/config.response")"
if [[ "$baseline_config_status" != "200" ]] || [[ "$protected_config_status" != "200" ]]; then
  cat "${baseline_dir}/config.response" >&2 || true
  cat "${protected_dir}/config.response" >&2 || true
  echo "Solr RunExecutableListener config API did not return 200" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected Solr container produced a detection during listener config" >&2
  exit 1
fi

baseline_update_status="$(trigger_commit "$baseline_port" "${baseline_dir}/update.response")"
protected_update_status="$(trigger_commit "$protected_port" "${protected_dir}/update.response")"
if [[ "$baseline_update_status" != "200" ]]; then
  cat "${baseline_dir}/update.response" >&2 || true
  echo "baseline Solr update did not return 200" >&2
  exit 1
fi
if [[ "$protected_update_status" =~ ^2 ]]; then
  cat "${protected_dir}/update.response" >&2 || true
  echo "protected Solr update unexpectedly returned ${protected_update_status}" >&2
  exit 1
fi

sleep 2
if [[ "$(marker_state "$baseline_name")" != "present" ]]; then
  cat "${baseline_dir}/update.response" >&2 || true
  echo "baseline Solr RunExecutableListener did not create ${marker}" >&2
  exit 1
fi
if [[ "$(marker_state "$protected_name")" != "missing" ]]; then
  cat "$protected_log" >&2 || true
  echo "protected Solr RunExecutableListener still created ${marker}" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Solr RunExecutableListener RCE" >&2
  exit 1
fi
if ! grep -q 'sh -c touch /tmp/ohmyrasp-solr12629-success' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing Solr RunExecutableListener command details in protected log" >&2
  exit 1
fi

echo "vulhub Solr CVE-2017-12629 RunExecutableListener Java8 acceptance passed"
