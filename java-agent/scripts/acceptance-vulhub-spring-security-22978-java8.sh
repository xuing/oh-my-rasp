#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_SECURITY_22978_IMAGE:-vulhub/spring-security:5.6.3}"
baseline_name="${OHMYRASP_VULHUB_SPRING_SECURITY_22978_BASELINE_NAME:-ohmyrasp-vulhub-spring22978-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_SECURITY_22978_PROTECTED_NAME:-ohmyrasp-vulhub-spring22978-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_SECURITY_22978_BASELINE_PORT:-19162}"
protected_port="${OHMYRASP_VULHUB_SPRING_SECURITY_22978_PROTECTED_PORT:-19163}"
baseline_dir="logs/vulhub-spring-security-5.6.3-java8-baseline"
protected_dir="logs/vulhub-spring-security-5.6.3-java8-protected"
protected_log="${protected_dir}/events.jsonl"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_home() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status

  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q 'CVE-2022-22978' "$output"; then
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring Security CVE-2022-22978 home page at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Spring Security container" >&2
    exit 1
  fi
  if ! grep -q '"request_hook":"installed"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2
    echo "missing Java 8 request hook startup marker in protected Spring Security container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    sed -n '1,160p' "$protected_log" >&2
    echo "protected Spring Security container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

fetch_path() {
  local port="$1"
  local path="$2"
  local output="$3"

  curl -sS --path-as-is -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}${path}" || true
}

assert_forbidden_admin() {
  local port="$1"
  local output="$2"
  local status

  status="$(fetch_path "$port" "/admin/index" "$output")"
  if [[ "$status" != "403" ]] || ! grep -q 'Forbidden / Access denied' "$output"; then
    sed -n '1,120p' "$output" >&2 || true
    echo "plain /admin/index was not denied with 403 on port ${port}" >&2
    exit 1
  fi
}

assert_baseline_bypass() {
  local port="$1"
  local suffix="$2"
  local output="$3"
  local status

  status="$(fetch_path "$port" "/admin/${suffix}test" "$output")"
  if [[ "$status" != "200" ]] || ! grep -q 'Congratulations, you are an admin' "$output"; then
    sed -n '1,120p' "$output" >&2 || true
    echo "baseline Spring Security ${suffix} path did not reach admin page" >&2
    exit 1
  fi
}

assert_protected_block() {
  local port="$1"
  local suffix="$2"
  local output="$3"
  local status

  status="$(fetch_path "$port" "/admin/${suffix}test" "$output")"
  if [[ "$status" == "200" ]] && grep -q 'Congratulations, you are an admin' "$output"; then
    sed -n '1,120p' "$output" >&2 || true
    echo "protected Spring Security ${suffix} path disclosed admin page" >&2
    exit 1
  fi
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

wait_for_home "$baseline_name" "$baseline_port" "${baseline_dir}/home.response"
wait_for_home "$protected_name" "$protected_port" "${protected_dir}/home.response"
expect_protected_startup_without_detection

assert_forbidden_admin "$baseline_port" "${baseline_dir}/admin-index.response"
assert_baseline_bypass "$baseline_port" "%0a" "${baseline_dir}/admin-lf.response"
assert_baseline_bypass "$baseline_port" "%0d" "${baseline_dir}/admin-cr.response"

assert_forbidden_admin "$protected_port" "${protected_dir}/admin-index.response"
assert_protected_block "$protected_port" "%0a" "${protected_dir}/admin-lf.response"
assert_protected_block "$protected_port" "%0d" "${protected_dir}/admin-cr.response"

if ! grep -q '"algorithm":"java8_request_path_confusion".*"action":"block".*/admin/%0atest' "$protected_log"; then
  sed -n '1,220p' "$protected_log" >&2
  echo "missing java8_request_path_confusion block event for Spring Security CVE-2022-22978 LF path" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_request_path_confusion".*"action":"block".*/admin/%0dtest' "$protected_log"; then
  sed -n '1,220p' "$protected_log" >&2
  echo "missing java8_request_path_confusion block event for Spring Security CVE-2022-22978 CR path" >&2
  exit 1
fi

echo "vulhub Spring Security CVE-2022-22978 Java8 acceptance passed"
