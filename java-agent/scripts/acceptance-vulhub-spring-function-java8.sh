#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_FUNCTION_IMAGE:-vulhub/spring-cloud-function:3.2.2}"
baseline_name="${OHMYRASP_VULHUB_SPRING_FUNCTION_BASELINE_NAME:-ohmyrasp-vulhub-spring22963-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_FUNCTION_PROTECTED_NAME:-ohmyrasp-vulhub-spring22963-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_FUNCTION_BASELINE_PORT:-19150}"
protected_port="${OHMYRASP_VULHUB_SPRING_FUNCTION_PROTECTED_PORT:-19151}"
baseline_dir="logs/vulhub-spring-cloud-function-3.2.2-java8-baseline"
protected_dir="logs/vulhub-spring-cloud-function-3.2.2-java8-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-spring22963-success"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_function() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}-uppercase.txt" -w "%{http_code}" \
      -H 'Content-Type: text/plain' \
      --data-binary test \
      "http://127.0.0.1:${port}/uppercase" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q 'TEST' "/tmp/${name}-uppercase.txt"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring Cloud Function uppercase endpoint at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Spring Cloud Function container" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Spring Cloud Function container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Spring Cloud Function container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

send_function_router_payload() {
  local port="$1"
  local output="$2"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: text/plain' \
    -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"touch ${success_file}\")" \
    --data-binary test \
    "http://127.0.0.1:${port}/functionRouter" || true
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

wait_for_function "$baseline_name" "$baseline_port"
wait_for_function "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_status="$(
  send_function_router_payload "$baseline_port" "${baseline_dir}/function-router.response"
)"
if [[ "$baseline_status" == "000" ]]; then
  cat "${baseline_dir}/function-router.response" >&2 || true
  echo "baseline Spring Cloud Function routing payload did not reach the server" >&2
  exit 1
fi
if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
  cat "${baseline_dir}/function-router.response" >&2 || true
  echo "baseline Spring Cloud Function did not create ${success_file}" >&2
  exit 1
fi

protected_status="$(
  send_function_router_payload "$protected_port" "${protected_dir}/function-router.response"
)"
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/function-router.response" >&2 || true
  echo "protected Spring Cloud Function routing payload did not reach the server" >&2
  exit 1
fi
if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
  echo "protected Spring Cloud Function created ${success_file} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Spring Cloud Function CVE-2022-22963" >&2
  exit 1
fi

echo "vulhub Spring Cloud Function CVE-2022-22963 Java8 acceptance passed"
