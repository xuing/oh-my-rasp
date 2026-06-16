#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_SPRING_BOOT_JETTY_IMAGE:-vulhub/spring-boot-jetty:3.2.4}"
baseline_name="${OHMYRASP_VULHUB_SPRING_BOOT_JETTY_BASELINE_NAME:-ohmyrasp-vulhub-spring41242-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_BOOT_JETTY_PROTECTED_NAME:-ohmyrasp-vulhub-spring41242-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_BOOT_JETTY_BASELINE_PORT:-18720}"
protected_port="${OHMYRASP_VULHUB_SPRING_BOOT_JETTY_PROTECTED_PORT:-18721}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-spring-boot-jetty-3.2.4-java17-baseline"
protected_dir="logs/vulhub-spring-boot-jetty-3.2.4-java17-protected"
protected_log="${protected_dir}/events.jsonl"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  "$image" \
  java -Djava.security.egd=file:/dev/./urandom \
    -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar \
    -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl \
    -Dohmyrasp.java17.block=true \
    -jar /app/app.jar >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" =~ ^2 ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Spring Boot Jetty at ${port}" >&2
  exit 1
}

send_ghost_bits_read() {
  local port="$1"
  local body_path="$2"
  local header_path="$3"
  python3 - "$port" "$body_path" "$header_path" <<'PY'
import socket
import sys

port = int(sys.argv[1])
body_path = sys.argv[2]
header_path = sys.argv[3]
ghost_bits_segment = bytes.fromhex("e998aee4b8a5e781b5e4b8b0e4b8b0e794b2e69da5")
path = b"/" + (ghost_bits_segment + b"/") * 7 + b"etc/passw%64"
request = (
    b"GET " + path + b" HTTP/1.1\r\n"
    + ("Host: 127.0.0.1:%d\r\n" % port).encode("ascii")
    + b"User-Agent: ohmyrasp-acceptance\r\n"
    + b"Connection: close\r\n\r\n"
)

with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
    sock.sendall(request)
    chunks = []
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            break
        chunks.append(chunk)

raw = b"".join(chunks)
headers, sep, body = raw.partition(b"\r\n\r\n")
with open(header_path, "wb") as handle:
    handle.write(headers + sep)
with open(body_path, "wb") as handle:
    handle.write(body)

first_line = headers.splitlines()[0].decode("ascii", "replace") if headers else ""
parts = first_line.split()
print(parts[1] if len(parts) > 1 else "000")
PY
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17 startup event in Spring Boot Jetty protected container" >&2
  exit 1
fi
if ! grep -q '"request_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing Java 17 request hook startup marker in Spring Boot Jetty protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Spring Boot Jetty protected startup produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(
  send_ghost_bits_read \
    "$baseline_port" \
    "${baseline_dir}/ghostbits-passwd.body" \
    "${baseline_dir}/ghostbits-passwd.headers"
)"
if [[ "$baseline_status" != "200" ]] \
    || ! grep -q '^root:.*:0:0:' "${baseline_dir}/ghostbits-passwd.body"; then
  cat "${baseline_dir}/ghostbits-passwd.headers" >&2 || true
  cat "${baseline_dir}/ghostbits-passwd.body" >&2 || true
  echo "baseline Spring Boot Jetty CVE-2025-41242 request did not read /etc/passwd" >&2
  exit 1
fi

protected_status="$(
  send_ghost_bits_read \
    "$protected_port" \
    "${protected_dir}/ghostbits-passwd.body" \
    "${protected_dir}/ghostbits-passwd.headers"
)"
if grep -q '^root:.*:0:0:' "${protected_dir}/ghostbits-passwd.body"; then
  cat "${protected_dir}/ghostbits-passwd.headers" >&2 || true
  cat "${protected_dir}/ghostbits-passwd.body" >&2 || true
  echo "protected Spring Boot Jetty CVE-2025-41242 request still read /etc/passwd" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java17_request_path_confusion".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_request_path_confusion block event for Spring Boot Jetty CVE-2025-41242" >&2
  exit 1
fi
if [[ "$protected_status" == "200" ]]; then
  cat "${protected_dir}/ghostbits-passwd.headers" >&2 || true
  cat "${protected_dir}/ghostbits-passwd.body" >&2 || true
  echo "protected Spring Boot Jetty CVE-2025-41242 request unexpectedly returned HTTP 200" >&2
  exit 1
fi

echo "vulhub Spring Boot Jetty 3.2.4 CVE-2025-41242 Java17 acceptance passed"
