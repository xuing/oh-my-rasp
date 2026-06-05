#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_MESSAGING_IMAGE:-vulhub/spring-messaging:5.0.4}"
baseline_name="${OHMYRASP_VULHUB_SPRING_MESSAGING_BASELINE_NAME:-ohmyrasp-vulhub-spring1270-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_MESSAGING_PROTECTED_NAME:-ohmyrasp-vulhub-spring1270-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_MESSAGING_BASELINE_PORT:-19156}"
protected_port="${OHMYRASP_VULHUB_SPRING_MESSAGING_PROTECTED_PORT:-19157}"
baseline_dir="logs/vulhub-spring-messaging-5.0.4-java8-baseline"
protected_dir="logs/vulhub-spring-messaging-5.0.4-java8-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-spring1270-success"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_sockjs() {
  local name="$1"
  local port="$2"
  local output="${3}"
  local status

  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/gs-guide-websocket/info?t=1" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q '"websocket":true' "$output"; then
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring Messaging SockJS info endpoint at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Spring Messaging container" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Spring Messaging container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    sed -n '1,160p' "$protected_log" >&2
    echo "protected Spring Messaging container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

send_sockjs_payload() {
  local port="$1"
  local marker="$2"
  local output="$3"

  python3 - "$port" "$marker" "$output" <<'PY'
import http.cookiejar
import json
import random
import string
import sys
import threading
import time
import urllib.error
import urllib.request

port = sys.argv[1]
marker = sys.argv[2]
output = sys.argv[3]
base_url = f"http://127.0.0.1:{port}/gs-guide-websocket"
letters = string.ascii_lowercase + string.digits
session_id = "".join(random.choice(letters) for _ in range(8))
root = f"{base_url}/{random.randint(0, 1000)}/{session_id}"
headers = {
    "Referer": base_url,
    "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
}
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)
records = [f"root {root}"]


def write_output():
    with open(output, "w", encoding="utf-8") as handle:
        handle.write("\n".join(records))
        handle.write("\n")


def stream():
    request = urllib.request.Request(f"{root}/htmlfile?c=_jp.vulhub", headers=headers)
    with opener.open(request, timeout=20) as response:
        while response.read(1):
            time.sleep(0.05)


def send(command, frame_headers, body=""):
    frame = (
        command.upper()
        + "\n"
        + "\n".join(f"{key}:{value}" for key, value in frame_headers.items())
        + "\n\n"
        + body
        + "\x00"
    )
    request_headers = dict(headers)
    request_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{root}/xhr_send?t={int(time.time() * 1000)}",
        data=json.dumps([frame]).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    try:
        with opener.open(request, timeout=20) as response:
            status = response.status
            response_body = response.read(120).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        status = error.code
        response_body = error.read(120).decode("utf-8", "replace")
    records.append(f"{command} {status} {response_body}")
    if status != 204:
        write_output()
        raise SystemExit(1)


threading.Thread(target=stream, daemon=True).start()
time.sleep(1)
send("connect", {"accept-version": "1.1,1.0", "heart-beat": "10000,10000"})
send(
    "subscribe",
    {
        "selector": f"T(java.lang.Runtime).getRuntime().exec('touch {marker}')",
        "id": "sub-0",
        "destination": "/topic/greetings",
    },
)
payload = json.dumps({"name": "vulhub"})
send("send", {"content-length": str(len(payload)), "destination": "/app/hello"}, payload)
time.sleep(2)
write_output()
PY
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_sockjs "$baseline_name" "$baseline_port" "${baseline_dir}/sockjs-info.json"
wait_for_sockjs "$protected_name" "$protected_port" "${protected_dir}/sockjs-info.json"
expect_protected_startup_without_detection

if ! send_sockjs_payload "$baseline_port" "$success_file" "${baseline_dir}/sockjs-exploit.out"; then
  sed -n '1,120p' "${baseline_dir}/sockjs-exploit.out" >&2 || true
  echo "baseline Spring Messaging SockJS/STOMP payload failed" >&2
  exit 1
fi
if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
  sed -n '1,120p' "${baseline_dir}/sockjs-exploit.out" >&2 || true
  echo "baseline Spring Messaging did not create ${success_file}" >&2
  exit 1
fi

if ! send_sockjs_payload "$protected_port" "$success_file" "${protected_dir}/sockjs-exploit.out"; then
  sed -n '1,120p' "${protected_dir}/sockjs-exploit.out" >&2 || true
  echo "protected Spring Messaging SockJS/STOMP payload failed" >&2
  exit 1
fi
if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
  echo "protected Spring Messaging created ${success_file} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  sed -n '1,200p' "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Spring Messaging CVE-2018-1270" >&2
  exit 1
fi

echo "vulhub Spring Messaging CVE-2018-1270 Java8 acceptance passed"
