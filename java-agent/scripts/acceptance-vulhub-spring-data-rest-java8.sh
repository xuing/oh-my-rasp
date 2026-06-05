#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_DATA_REST_IMAGE:-vulhub/spring-rest-data:2.6.6}"
baseline_name="${OHMYRASP_VULHUB_SPRING_DATA_REST_BASELINE_NAME:-ohmyrasp-vulhub-spring8046-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_DATA_REST_PROTECTED_NAME:-ohmyrasp-vulhub-spring8046-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_DATA_REST_BASELINE_PORT:-19152}"
protected_port="${OHMYRASP_VULHUB_SPRING_DATA_REST_PROTECTED_PORT:-19153}"
baseline_dir="logs/vulhub-spring-rest-data-2.6.6-java8-baseline"
protected_dir="logs/vulhub-spring-rest-data-2.6.6-java8-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-spring8046-success"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_patch_payload() {
  local output="$1"
  local marker="$2"
  python3 - "$output" "$marker" <<'PY'
import json
import sys

command = "/usr/bin/touch " + sys.argv[2]
byte_expr = ",".join(str(item) for item in command.encode("utf-8"))
payload = [
    {
        "op": "replace",
        "path": (
            "T(java.lang.Runtime).getRuntime().exec("
            "new java.lang.String(new byte[]{" + byte_expr + "}))/lastname"
        ),
        "value": "vulhub",
    }
]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY
}

wait_for_customer() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}-customer.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/customers/1" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q 'lastname' "/tmp/${name}-customer.json"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring Data REST customer resource at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Spring Data REST container" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Spring Data REST container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Spring Data REST container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

send_patch_payload() {
  local port="$1"
  local payload="$2"
  local output="$3"
  curl -sS -o "$output" -w "%{http_code}" \
    -X PATCH \
    -H 'Content-Type: application/json-patch+json' \
    --data-binary "@${payload}" \
    "http://127.0.0.1:${port}/customers/1" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

baseline_payload="${baseline_dir}/json-patch-payload.json"
protected_payload="${protected_dir}/json-patch-payload.json"
write_patch_payload "$baseline_payload" "$success_file"
write_patch_payload "$protected_payload" "$success_file"

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_customer "$baseline_name" "$baseline_port"
wait_for_customer "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_status="$(
  send_patch_payload "$baseline_port" "$baseline_payload" "${baseline_dir}/patch.response"
)"
if [[ "$baseline_status" == "000" ]]; then
  cat "${baseline_dir}/patch.response" >&2 || true
  echo "baseline Spring Data REST JSON Patch payload did not reach the server" >&2
  exit 1
fi
if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
  cat "${baseline_dir}/patch.response" >&2 || true
  echo "baseline Spring Data REST did not create ${success_file}" >&2
  exit 1
fi

protected_status="$(
  send_patch_payload "$protected_port" "$protected_payload" "${protected_dir}/patch.response"
)"
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/patch.response" >&2 || true
  echo "protected Spring Data REST JSON Patch payload did not reach the server" >&2
  exit 1
fi
if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
  echo "protected Spring Data REST created ${success_file} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Spring Data REST CVE-2017-8046" >&2
  exit 1
fi

echo "vulhub Spring Data REST CVE-2017-8046 Java8 acceptance passed"
