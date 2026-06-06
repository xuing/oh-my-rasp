#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SKYWALKING_IMAGE:-vulhub/skywalking:8.3.0}"
baseline_network="${OHMYRASP_VULHUB_SKYWALKING_BASELINE_NET:-ohmyrasp-vulhub-skywalking830-baseline-net}"
protected_network="${OHMYRASP_VULHUB_SKYWALKING_PROTECTED_NET:-ohmyrasp-vulhub-skywalking830-protected-net}"
baseline_oap_name="${OHMYRASP_VULHUB_SKYWALKING_BASELINE_OAP_NAME:-ohmyrasp-vulhub-skywalking830-baseline-oap}"
baseline_web_name="${OHMYRASP_VULHUB_SKYWALKING_BASELINE_WEB_NAME:-ohmyrasp-vulhub-skywalking830-baseline-web}"
protected_oap_name="${OHMYRASP_VULHUB_SKYWALKING_PROTECTED_OAP_NAME:-ohmyrasp-vulhub-skywalking830-protected-oap}"
protected_web_name="${OHMYRASP_VULHUB_SKYWALKING_PROTECTED_WEB_NAME:-ohmyrasp-vulhub-skywalking830-protected-web}"
baseline_port="${OHMYRASP_VULHUB_SKYWALKING_BASELINE_PORT:-18860}"
protected_port="${OHMYRASP_VULHUB_SKYWALKING_PROTECTED_PORT:-18861}"
baseline_dir="logs/vulhub-skywalking-8.3.0-java8-baseline"
protected_dir="logs/vulhub-skywalking-8.3.0-java8-protected"
protected_log="${protected_dir}/events.jsonl"
safe_metric="service_instance_jvm_memory.max"
malicious_metric="sqli/**/where/**/1=1--"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  local label="$3"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/${label}.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_oap_name" "$baseline_dir" "oap"
  copy_artifacts "$baseline_web_name" "$baseline_dir" "web"
  copy_artifacts "$protected_oap_name" "$protected_dir" "oap"
  copy_artifacts "$protected_web_name" "$protected_dir" "web"
  docker rm -f \
    "$baseline_oap_name" "$baseline_web_name" \
    "$protected_oap_name" "$protected_web_name" >/dev/null 2>&1 || true
  docker network rm "$baseline_network" "$protected_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_payload() {
  local metric_name="$1"
  local output="$2"
  python3 - "$metric_name" "$output" <<'PY'
import json
import sys

metric_name, output = sys.argv[1], sys.argv[2]
payload = {
    "query": (
        "query queryLogs($condition: LogQueryCondition){"
        "queryLogs(condition:$condition){"
        "total logs{serviceId serviceName isError content}"
        "}}"
    ),
    "variables": {
        "condition": {
            "metricName": metric_name,
            "state": "ALL",
            "paging": {"pageSize": 10},
        }
    },
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY
}

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 30 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

post_graphql() {
  local port="$1"
  local payload="$2"
  local output="$3"
  curl_status "$output" \
    -H "Content-Type: application/json" \
    --data-binary "@${payload}" \
    "http://127.0.0.1:${port}/graphql"
}

wait_for_web() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/web-ready-${attempt}.response" "http://127.0.0.1:${port}/")"
    printf 'web_ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "SkyWalking web container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "SkyWalking web container ${name} did not become ready at ${port}" >&2
  exit 1
}

wait_for_graphql_status() {
  local port="$1"
  local payload="$2"
  local dir="$3"
  local label="$4"
  local status
  for attempt in $(seq 1 90); do
    status="$(post_graphql "$port" "$payload" "${dir}/${label}-ready-${attempt}.response")"
    printf '%s_ready_attempt=%s status=%s\n' "$label" "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 2
  done
  cat "${dir}/${label}-ready-"*.response >&2 || true
  echo "SkyWalking GraphQL endpoint did not become ready on ${port}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log" \
      && grep -Fq '"sql_identifier_hook":"installed"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup/sql-identifier marker for protected SkyWalking OAP" >&2
  exit 1
}

detection_count() {
  grep -Fc '"event":"ohmyrasp-detection"' "$protected_log" 2>/dev/null || true
}

sql_identifier_block_count() {
  grep -Ec '"algorithm":"java8_sql_identifier_injection".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_sql_identifier_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(sql_identifier_block_count)"
    if (( count > previous )); then
      printf 'sql_identifier_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_sql_identifier_injection block event for SkyWalking 8.3.0" >&2
  exit 1
}

verify_image_java8() {
  docker run --rm "$image" java -version > "${baseline_dir}/image-java-version.txt" 2>&1 || true
  if ! grep -Fq '1.8.0_' "${baseline_dir}/image-java-version.txt"; then
    cat "${baseline_dir}/image-java-version.txt" >&2 || true
    echo "SkyWalking 8.3.0 image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

run_baseline() {
  local status
  docker network create "$baseline_network" >/dev/null
  docker run -d --name "$baseline_oap_name" \
    --network "$baseline_network" --network-alias oap \
    "$image" bash bin/oap-service.sh >/dev/null
  docker run -d --name "$baseline_web_name" \
    --network "$baseline_network" \
    -p "${baseline_port}:8080" \
    -e "COLLECTOR_RIBBON_LISTOFSERVERS=oap:12800" \
    "$image" bash bin/web-server.sh >/dev/null

  wait_for_web "$baseline_web_name" "$baseline_port" "$baseline_dir"
  wait_for_graphql_status "$baseline_port" "${baseline_dir}/safe-query.json" "$baseline_dir" "graphql"

  for attempt in $(seq 1 30); do
    status="$(post_graphql "$baseline_port" "${baseline_dir}/malicious-query.json" "${baseline_dir}/malicious-${attempt}.response")"
    printf 'malicious_attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if [[ "$status" == "200" ]] \
      && grep -Fq 'select count(1) total from' "${baseline_dir}/malicious-${attempt}.response" \
      && grep -Fq "$malicious_metric" "${baseline_dir}/malicious-${attempt}.response"; then
      cp "${baseline_dir}/malicious-${attempt}.response" "${baseline_dir}/malicious-success.response"
      return
    fi
    sleep 2
  done

  cat "${baseline_dir}"/malicious-*.response >&2 || true
  echo "baseline SkyWalking 8.3.0 did not expose the H2 metricName SQL injection" >&2
  exit 1
}

run_protected() {
  local before_count
  local safe_count
  local status

  docker network create "$protected_network" >/dev/null
  docker run -d --name "$protected_oap_name" \
    --network "$protected_network" --network-alias oap \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" bash bin/oap-service.sh >/dev/null
  docker run -d --name "$protected_web_name" \
    --network "$protected_network" \
    -p "${protected_port}:8080" \
    -e "COLLECTOR_RIBBON_LISTOFSERVERS=oap:12800" \
    "$image" bash bin/web-server.sh >/dev/null

  wait_for_protected_startup
  if [[ "$(detection_count)" != "0" ]]; then
    cat "$protected_log" >&2
    echo "SkyWalking protected OAP produced a detection before exploit traffic" >&2
    exit 1
  fi
  wait_for_web "$protected_web_name" "$protected_port" "$protected_dir"
  wait_for_graphql_status "$protected_port" "${protected_dir}/safe-query.json" "$protected_dir" "graphql"
  if grep -Fq 'OhMyRASP' "${protected_dir}/graphql-ready-"*.response; then
    cat "${protected_dir}/graphql-ready-"*.response >&2 || true
    echo "safe SkyWalking metricName request was blocked unexpectedly" >&2
    exit 1
  fi
  safe_count="$(detection_count)"
  if [[ "$safe_count" != "0" ]]; then
    cat "$protected_log" >&2
    echo "safe SkyWalking metricName request produced a RASP detection" >&2
    exit 1
  fi

  before_count="$(sql_identifier_block_count)"
  for attempt in $(seq 1 30); do
    status="$(post_graphql "$protected_port" "${protected_dir}/malicious-query.json" "${protected_dir}/malicious-${attempt}.response")"
    printf 'malicious_attempt=%s status=%s\n' "$attempt" "$status" >> "${protected_dir}/attempts.log"
    if [[ "$status" == "200" ]] \
      && grep -Fq 'OhMyRASP Java 8 blocked suspicious SQL identifier' "${protected_dir}/malicious-${attempt}.response"; then
      cp "${protected_dir}/malicious-${attempt}.response" "${protected_dir}/malicious-blocked.response"
      wait_for_sql_identifier_block "$before_count"
      if grep -Fq "$malicious_metric" "$protected_log"; then
        cat "$protected_log" >&2
        echo "protected SkyWalking event log included the raw malicious metricName" >&2
        exit 1
      fi
      return
    fi
    sleep 2
  done

  cat "$protected_log" >&2 || true
  cat "${protected_dir}"/malicious-*.response >&2 || true
  echo "protected SkyWalking 8.3.0 did not block the metricName SQL identifier injection" >&2
  exit 1
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f \
  "$baseline_oap_name" "$baseline_web_name" \
  "$protected_oap_name" "$protected_web_name" >/dev/null 2>&1 || true
docker network rm "$baseline_network" "$protected_network" >/dev/null 2>&1 || true

write_payload "$safe_metric" "${baseline_dir}/safe-query.json"
write_payload "$malicious_metric" "${baseline_dir}/malicious-query.json"
write_payload "$safe_metric" "${protected_dir}/safe-query.json"
write_payload "$malicious_metric" "${protected_dir}/malicious-query.json"

verify_image_java8
run_baseline
run_protected

copy_artifacts "$baseline_oap_name" "$baseline_dir" "oap"
copy_artifacts "$baseline_web_name" "$baseline_dir" "web"
copy_artifacts "$protected_oap_name" "$protected_dir" "oap"
copy_artifacts "$protected_web_name" "$protected_dir" "web"
docker rm -f \
  "$baseline_oap_name" "$baseline_web_name" \
  "$protected_oap_name" "$protected_web_name" >/dev/null 2>&1 || true
docker network rm "$baseline_network" "$protected_network" >/dev/null 2>&1 || true

echo "vulhub SkyWalking 8.3.0 Java8 acceptance passed"
