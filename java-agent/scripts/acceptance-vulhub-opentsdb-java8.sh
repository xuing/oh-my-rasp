#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image_35476="${OHMYRASP_VULHUB_OPENTSDB_35476_IMAGE:-vulhub/opentsdb:2.4.0}"
image_25826="${OHMYRASP_VULHUB_OPENTSDB_25826_IMAGE:-vulhub/opentsdb:2.4.1}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
base_dir="logs/vulhub-opentsdb-java8"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$base_dir"
mkdir -p "$base_dir"

containers=()

cleanup() {
  local name
  for name in "${containers[@]}"; do
    local dir="${base_dir}/${name}"
    mkdir -p "$dir"
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

wait_for_http() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl --max-time 3 -sS -o "${dir}/ready-${attempt}.html" -w "%{http_code}" \
        "http://127.0.0.1:${port}/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    if ! docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; then
      echo "OpenTSDB container ${name} exited before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  echo "OpenTSDB container ${name} did not become ready" >&2
  exit 1
}

start_container() {
  local name="$1"
  local image="$2"
  local protected="$3"
  local dir="$4"
  docker rm -f "$name" >/dev/null 2>&1 || true
  if [[ "$protected" == "true" ]]; then
    rm -f "${dir}/events.jsonl"
    docker run -d --name "$name" \
      -p 127.0.0.1::4242 \
      -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
      -v "$(pwd)/${dir}:/opt/ohmyrasp/logs" \
      -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
      "$image" >/dev/null
  else
    docker run -d --name "$name" \
      -p 127.0.0.1::4242 \
      "$image" >/dev/null
  fi
  containers+=("$name")
  docker port "$name" 4242/tcp | sed 's/.*://'
}

put_metric() {
  local port="$1"
  local dir="$2"
  curl -sS -X POST \
    -H 'Content-Type: application/json' \
    --data-binary '{"metric":"sys.cpu.nice","timestamp":1346846400,"value":20,"tags":{"host":"web01","dc":"lga"}}' \
    "http://127.0.0.1:${port}/api/put/" \
    -o "${dir}/put.response" \
    -w "put_status=%{http_code}\n" >> "${dir}/attempts.log"
  if ! grep -Fq 'put_status=204' "${dir}/attempts.log"; then
    cat "${dir}/put.response" >&2 || true
    echo "OpenTSDB metric creation did not return HTTP 204" >&2
    exit 1
  fi
}

wait_for_metric() {
  local port="$1"
  local dir="$2"
  for attempt in $(seq 1 45); do
    curl -sS \
      "http://127.0.0.1:${port}/api/query?start=2000/10/21-00:00:00&m=sum:sys.cpu.nice" \
      -o "${dir}/query-${attempt}.json" || true
    printf 'metric_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if grep -Fq '1346846400' "${dir}/query-${attempt}.json"; then
      printf 'metric_visible=1\n' >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done
  echo "OpenTSDB metric did not become query-visible" >&2
  exit 1
}

wait_for_marker() {
  local name="$1"
  local marker="$2"
  local dir="$3"
  for attempt in $(seq 1 30); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if docker exec "$name" test -f "$marker"; then
      printf 'marker_created=1\n' >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done
  echo "OpenTSDB baseline did not create ${marker}" >&2
  exit 1
}

assert_marker_absent() {
  local name="$1"
  local marker="$2"
  local dir="$3"
  if docker exec "$name" test -f "$marker"; then
    echo "OpenTSDB protected container still created ${marker}" >&2
    exit 1
  fi
  printf 'marker_absent=1\n' >> "${dir}/attempts.log"
}

assert_protected_startup_quiet() {
  local log="$1"
  if grep -Fq '"event":"ohmyrasp-detection"' "$log" 2>/dev/null; then
    cat "$log" >&2 || true
    echo "OpenTSDB protected startup produced a detection before exploit traffic" >&2
    exit 1
  fi
}

wait_for_plot_block() {
  local log="$1"
  local dir="$2"
  for attempt in $(seq 1 30); do
    printf 'plot_block_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
    if grep -Eq '"algorithm":"java8_file_generated_plot_script_command".*"action":"block"' "$log" 2>/dev/null; then
      return
    fi
    sleep 1
  done
  cat "$log" >&2 2>/dev/null || true
  echo "missing java8_file_generated_plot_script_command block event for OpenTSDB" >&2
  exit 1
}

exploit_35476() {
  local port="$1"
  local marker="$2"
  local dir="$3"
  local path="/q?start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[0:system(%27touch%20${marker}%27)]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
  curl --globoff -sS --path-as-is \
    "http://127.0.0.1:${port}${path}" \
    -o "${dir}/exploit.response" \
    -w "exploit_status=%{http_code}\n" >> "${dir}/attempts.log" || true
}

exploit_25826() {
  local port="$1"
  local marker="$2"
  local dir="$3"
  local path="/q?start=2000/10/21-00:00:00&m=sum:sys.cpu.nice&o=&ylabel=1&xrange=&y2range=[42:42]&key=%3Bsystem%20%22touch%20${marker}%22%20%22&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
  curl --globoff -sS --path-as-is \
    "http://127.0.0.1:${port}${path}" \
    -o "${dir}/exploit.response" \
    -w "exploit_status=%{http_code}\n" >> "${dir}/attempts.log" || true
}

run_case() {
  local suffix="$1"
  local image="$2"
  local marker="$3"
  local exploit_fn="$4"

  local baseline_name="ohmyrasp-vulhub-opentsdb-${suffix}-baseline"
  local protected_name="ohmyrasp-vulhub-opentsdb-${suffix}-protected"
  local baseline_dir="${base_dir}/${baseline_name}"
  local protected_dir="${base_dir}/${protected_name}"
  local protected_log="${protected_dir}/events.jsonl"
  mkdir -p "$baseline_dir" "$protected_dir"

  local port
  port="$(start_container "$baseline_name" "$image" false "$baseline_dir")"
  printf 'opentsdb_port=%s\n' "$port" >> "${baseline_dir}/attempts.log"
  wait_for_http "$baseline_name" "$port" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$marker"
  put_metric "$port" "$baseline_dir"
  wait_for_metric "$port" "$baseline_dir"
  "$exploit_fn" "$port" "$marker" "$baseline_dir"
  wait_for_marker "$baseline_name" "$marker" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true

  port="$(start_container "$protected_name" "$image" true "$protected_dir")"
  printf 'opentsdb_port=%s\n' "$port" >> "${protected_dir}/attempts.log"
  wait_for_http "$protected_name" "$port" "$protected_dir"
  assert_protected_startup_quiet "$protected_log"
  docker exec "$protected_name" rm -f "$marker"
  put_metric "$port" "$protected_dir"
  wait_for_metric "$port" "$protected_dir"
  "$exploit_fn" "$port" "$marker" "$protected_dir"
  wait_for_plot_block "$protected_log" "$protected_dir"
  sleep 5
  assert_marker_absent "$protected_name" "$marker" "$protected_dir"
  docker rm -f "$protected_name" >/dev/null 2>&1 || true
}

run_case "35476" "$image_35476" "/tmp/ohmyrasp-opentsdb-35476-success" exploit_35476
run_case "25826" "$image_25826" "/tmp/ohmyrasp-opentsdb-25826-success" exploit_25826

echo "vulhub OpenTSDB 2.4.0/2.4.1 Gnuplot Java8 acceptance passed"
