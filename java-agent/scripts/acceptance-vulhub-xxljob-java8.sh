#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

admin_image="${OHMYRASP_VULHUB_XXLJOB_ADMIN_IMAGE:-vulhub/xxl-job:2.2.0-admin}"
executor_image="${OHMYRASP_VULHUB_XXLJOB_EXECUTOR_IMAGE:-vulhub/xxl-job:2.2.0-executor}"
db_image="${OHMYRASP_VULHUB_XXLJOB_DB_IMAGE:-mysql:5.7}"
baseline_project="${OHMYRASP_VULHUB_XXLJOB_BASELINE_PROJECT:-ohmyrasp-vulhub-xxljob-baseline}"
protected_project="${OHMYRASP_VULHUB_XXLJOB_PROTECTED_PROJECT:-ohmyrasp-vulhub-xxljob-protected}"
marker="${OHMYRASP_VULHUB_XXLJOB_MARKER:-/tmp/ohmyrasp-xxljob-success}"
baseline_dir="logs/vulhub-xxljob-unacc-java8-baseline"
protected_dir="logs/vulhub-xxljob-unacc-java8-protected"
protected_log="${protected_dir}/events.jsonl"
payload='{"jobId":1,"executorHandler":"demoJobHandler","executorParams":"demoJobHandler","executorBlockStrategy":"COVER_EARLY","executorTimeout":0,"logId":1,"logDateTime":1586629003729,"glueType":"GLUE_SHELL","glueSource":"touch /tmp/ohmyrasp-xxljob-success","glueUpdatetime":1586699003758,"broadcastIndex":0,"broadcastTotal":0}'

mkdir -p "$baseline_dir" "$protected_dir"

copy_artifacts() {
  local project="$1"
  local dir="$2"
  for service in db admin executor; do
    local name="${project}-${service}"
    if docker inspect "$name" >/dev/null 2>&1; then
      docker logs "$name" > "${dir}/${service}.log" 2>&1 || true
    fi
  done
}

cleanup_project() {
  local project="$1"
  docker rm -f \
    "${project}-executor" \
    "${project}-admin" \
    "${project}-db" >/dev/null 2>&1 || true
  docker network rm "$project" >/dev/null 2>&1 || true
}

cleanup() {
  copy_artifacts "$baseline_project" "$baseline_dir"
  copy_artifacts "$protected_project" "$protected_dir"
  cleanup_project "$baseline_project"
  cleanup_project "$protected_project"
}
trap cleanup EXIT

start_stack() {
  local project="$1"
  local protected="$2"
  local log_dir="$3"
  cleanup_project "$project"
  docker network create "$project" >/dev/null
  docker run -d --name "${project}-db" \
    --network "$project" \
    --network-alias db \
    -e MYSQL_ROOT_PASSWORD=root \
    "$db_image" >/dev/null
  docker run -d --name "${project}-admin" \
    --network "$project" \
    --network-alias admin \
    "$admin_image" >/dev/null
  if [[ "$protected" == "true" ]]; then
    rm -f "${log_dir}/events.jsonl"
    docker run -d --name "${project}-executor" \
      --network "$project" \
      --network-alias executor \
      -p 127.0.0.1::9999 \
      -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
      -v "$(pwd)/${log_dir}:/opt/ohmyrasp/logs" \
      -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
      "$executor_image" >/dev/null
  else
    docker run -d --name "${project}-executor" \
      --network "$project" \
      --network-alias executor \
      -p 127.0.0.1::9999 \
      "$executor_image" >/dev/null
  fi
  docker port "${project}-executor" 9999/tcp | sed 's/.*://'
}

wait_for_executor() {
  local project="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl --max-time 3 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" != "000" ]]; then
      return
    fi
    sleep 2
  done
  copy_artifacts "$project" "$dir"
  echo "XXL-JOB executor did not become ready for ${project}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log" 2>/dev/null; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 2>/dev/null || true
  echo "missing Java8 agent startup event for XXL-JOB protected executor" >&2
  exit 1
}

trigger_run() {
  local port="$1"
  local output="$2"
  curl -sS -m 20 -w '\nHTTP_STATUS:%{http_code}\n' \
    -X POST \
    -H 'Content-Type: application/json' \
    --data-binary "$payload" \
    "http://127.0.0.1:${port}/run" > "$output"
}

wait_for_marker() {
  local project="$1"
  local dir="$2"
  for attempt in $(seq 1 30); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if docker exec "${project}-executor" test -f "$marker"; then
      return
    fi
    sleep 1
  done
  copy_artifacts "$project" "$dir"
  echo "XXL-JOB baseline did not create ${marker}" >&2
  exit 1
}

run_baseline() {
  local port
  port="$(start_stack "$baseline_project" false "$baseline_dir")"
  printf 'executor_port=%s\n' "$port" >> "${baseline_dir}/attempts.log"
  wait_for_executor "$baseline_project" "$port" "$baseline_dir"
  docker exec "${baseline_project}-executor" rm -f "$marker"
  trigger_run "$port" "${baseline_dir}/run.response"
  if ! grep -q 'HTTP_STATUS:200' "${baseline_dir}/run.response"; then
    cat "${baseline_dir}/run.response" >&2 || true
    echo "XXL-JOB baseline /run did not return HTTP 200" >&2
    exit 1
  fi
  wait_for_marker "$baseline_project" "$baseline_dir"
  copy_artifacts "$baseline_project" "$baseline_dir"
  cleanup_project "$baseline_project"
}

run_protected() {
  local port
  port="$(start_stack "$protected_project" true "$protected_dir")"
  printf 'executor_port=%s\n' "$port" >> "${protected_dir}/attempts.log"
  wait_for_protected_startup
  wait_for_executor "$protected_project" "$port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "XXL-JOB protected startup produced a detection before exploit traffic" >&2
    exit 1
  fi
  docker exec "${protected_project}-executor" rm -f "$marker"
  trigger_run "$port" "${protected_dir}/run.response"
  sleep 3
  if docker exec "${protected_project}-executor" test -f "$marker"; then
    copy_artifacts "$protected_project" "$protected_dir"
    echo "XXL-JOB protected executor still created ${marker}" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_command_execution_shell_meta".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing java8_command_execution_shell_meta block event for XXL-JOB /run" >&2
    exit 1
  fi
  copy_artifacts "$protected_project" "$protected_dir"
  cleanup_project "$protected_project"
}

run_baseline
run_protected

echo "vulhub XXL-JOB 2.2.0 executor unauth Java8 acceptance passed"
