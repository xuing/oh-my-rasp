#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_UNOMI_IMAGE:-vulhub/unomi:1.5.1}"
es_image="${OHMYRASP_VULHUB_UNOMI_ES_IMAGE:-elasticsearch:7.9.3}"
baseline_name="${OHMYRASP_VULHUB_UNOMI_BASELINE_NAME:-ohmyrasp-vulhub-unomi-13942-baseline}"
baseline_es_name="${OHMYRASP_VULHUB_UNOMI_BASELINE_ES_NAME:-ohmyrasp-vulhub-unomi-13942-baseline-es}"
protected_name="${OHMYRASP_VULHUB_UNOMI_PROTECTED_NAME:-ohmyrasp-vulhub-unomi-13942-protected}"
protected_es_name="${OHMYRASP_VULHUB_UNOMI_PROTECTED_ES_NAME:-ohmyrasp-vulhub-unomi-13942-protected-es}"
baseline_net="${OHMYRASP_VULHUB_UNOMI_BASELINE_NET:-ohmyrasp-vulhub-unomi-13942-baseline-net}"
protected_net="${OHMYRASP_VULHUB_UNOMI_PROTECTED_NET:-ohmyrasp-vulhub-unomi-13942-protected-net}"
baseline_port="${OHMYRASP_VULHUB_UNOMI_BASELINE_PORT:-19181}"
protected_port="${OHMYRASP_VULHUB_UNOMI_PROTECTED_PORT:-19182}"
baseline_dir="logs/vulhub-unomi-2020-13942-java8-baseline"
protected_dir="logs/vulhub-unomi-2020-13942-java8-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-unomi-touch-success"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_es_name" "$baseline_dir/elasticsearch"
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_es_name" "$protected_dir/elasticsearch"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$baseline_es_name" "$protected_name" "$protected_es_name" >/dev/null 2>&1 || true
  docker network rm "$baseline_net" "$protected_net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_payload() {
  local output="$1"
  cat > "$output" <<'JSON'
{
  "filters": [
    {
      "id": "sample",
      "filters": [
        {
          "condition": {
            "parameterValues": {
              "": "script::Runtime r = Runtime.getRuntime(); r.exec(\"touch /tmp/ohmyrasp-unomi-touch-success\");"
            },
            "type": "profilePropertyCondition"
          }
        }
      ]
    }
  ],
  "sessionId": "sample"
}
JSON
}

start_elasticsearch() {
  local name="$1"
  local network="$2"
  local dir="$3"
  docker run -d --name "$name" \
    --network "$network" --network-alias elasticsearch \
    -e cluster.name=contextElasticSearch \
    -e discovery.type=single-node \
    -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
    -e bootstrap.memory_lock=true \
    "$es_image" >/dev/null

  for attempt in $(seq 1 120); do
    if docker logs "$name" 2>&1 | grep -q "started"; then
      printf 'elasticsearch_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Elasticsearch did not start for Unomi CVE-2020-13942" >&2
  exit 1
}

wait_for_context() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(
      curl --max-time 5 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/context.json" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "400" ]]; then
      return
    fi
    if [[ "$status" == "500" ]] \
      && grep -Eq 'NoClassDefFoundError: io/ohmyrasp/agent/java8/Java8RaspHooks|VerifyError' \
        "${dir}/ready-${attempt}.response"; then
      cat "${dir}/ready-${attempt}.response" >&2
      echo "Unomi protected servlet hook failed before readiness" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Unomi did not become ready on /context.json at ${port}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java8 agent startup event for Unomi protected container" >&2
  exit 1
}

post_context() {
  local port="$1"
  local payload="$2"
  local output="$3"
  local status
  status="$(
    curl --max-time 20 -sS -o "$output" -w "%{http_code}" \
      -H "Content-Type: application/json" \
      --data-binary "@${payload}" \
      "http://127.0.0.1:${port}/context.json" 2>/dev/null || true
  )"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s' "$status"
}

run_baseline() {
  local payload="${baseline_dir}/context-payload.json"
  local status
  write_payload "$payload"
  docker network create "$baseline_net" >/dev/null
  start_elasticsearch "$baseline_es_name" "$baseline_net" "$baseline_dir"
  docker run -d --name "$baseline_name" \
    --network "$baseline_net" \
    -p "${baseline_port}:8181" \
    -e UNOMI_ELASTICSEARCH_ADDRESSES=elasticsearch:9200 \
    "$image" >/dev/null

  wait_for_context "$baseline_name" "$baseline_port" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$success_file"
  status="$(post_context "$baseline_port" "$payload" "${baseline_dir}/context-baseline.response")"
  printf 'baseline_payload_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]]; then
    cat "${baseline_dir}/context-baseline.response" >&2 || true
    echo "baseline Unomi returned unexpected status ${status}" >&2
    exit 1
  fi
  for _ in $(seq 1 10); do
    if docker exec "$baseline_name" test -e "$success_file"; then
      copy_artifacts "$baseline_es_name" "$baseline_dir/elasticsearch"
      copy_artifacts "$baseline_name" "$baseline_dir"
      docker rm -f "$baseline_name" "$baseline_es_name" >/dev/null 2>&1 || true
      docker network rm "$baseline_net" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done
  cat "${baseline_dir}/context-baseline.response" >&2 || true
  echo "baseline Unomi did not execute the MVEL Runtime.exec payload" >&2
  exit 1
}

run_protected() {
  local payload="${protected_dir}/context-payload.json"
  local status
  write_payload "$payload"
  docker network create "$protected_net" >/dev/null
  start_elasticsearch "$protected_es_name" "$protected_net" "$protected_dir"
  docker run -d --name "$protected_name" \
    --network "$protected_net" \
    -p "${protected_port}:8181" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e UNOMI_ELASTICSEARCH_ADDRESSES=elasticsearch:9200 \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_context "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Unomi protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  status="$(post_context "$protected_port" "$payload" "${protected_dir}/context-protected.response")"
  printf 'protected_payload_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if [[ "$status" != "200" ]]; then
    cat "${protected_dir}/context-protected.response" >&2 || true
    echo "protected Unomi returned unexpected status ${status}" >&2
    exit 1
  fi
  sleep 2
  if docker exec "$protected_name" test -e "$success_file"; then
    echo "protected Unomi created ${success_file} despite Java8 RASP" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    cat "${protected_dir}/context-protected.response" >&2 || true
    echo "missing java8_command_execution_exploit_primitive block event for Unomi CVE-2020-13942" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir/elasticsearch" "$protected_dir/elasticsearch"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$baseline_es_name" "$protected_name" "$protected_es_name" >/dev/null 2>&1 || true
docker network rm "$baseline_net" "$protected_net" >/dev/null 2>&1 || true

run_baseline
run_protected

copy_artifacts "$protected_es_name" "$protected_dir/elasticsearch"
copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" "$protected_es_name" >/dev/null 2>&1 || true
docker network rm "$protected_net" >/dev/null 2>&1 || true

echo "vulhub Unomi CVE-2020-13942 Java8 acceptance passed"
