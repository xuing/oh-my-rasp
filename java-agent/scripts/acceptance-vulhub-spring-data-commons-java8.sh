#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_DATA_COMMONS_IMAGE:-vulhub/spring-data-commons:2.0.5}"
baseline_name="${OHMYRASP_VULHUB_SPRING_DATA_COMMONS_BASELINE_NAME:-ohmyrasp-vulhub-spring1273-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_DATA_COMMONS_PROTECTED_NAME:-ohmyrasp-vulhub-spring1273-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_DATA_COMMONS_BASELINE_PORT:-19154}"
protected_port="${OHMYRASP_VULHUB_SPRING_DATA_COMMONS_PROTECTED_PORT:-19155}"
baseline_dir="logs/vulhub-spring-data-commons-2.0.5-java8-baseline"
protected_dir="logs/vulhub-spring-data-commons-2.0.5-java8-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-spring1273-success"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_form_body() {
  local output="$1"
  local marker="$2"
  python3 - "$output" "$marker" <<'PY'
import sys
from urllib.parse import urlencode

param = (
    "username[#this.getClass().forName(\"java.lang.Runtime\")"
    ".getRuntime().exec(\"touch " + sys.argv[2] + "\")]"
)
body = urlencode({param: "", "password": "", "repeatedPassword": ""})
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    handle.write(body)
PY
}

wait_for_users() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}-users.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/users" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -qi 'user' "/tmp/${name}-users.html"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring Data Commons users page at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Spring Data Commons container" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Spring Data Commons container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Spring Data Commons container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

send_form_payload() {
  local port="$1"
  local body="$2"
  local output="$3"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary "@${body}" \
    "http://127.0.0.1:${port}/users?page=&size=5" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

baseline_body="${baseline_dir}/form-body.txt"
protected_body="${protected_dir}/form-body.txt"
write_form_body "$baseline_body" "$success_file"
write_form_body "$protected_body" "$success_file"

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_users "$baseline_name" "$baseline_port"
wait_for_users "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_status="$(
  send_form_payload "$baseline_port" "$baseline_body" "${baseline_dir}/register.response"
)"
if [[ "$baseline_status" == "000" ]]; then
  cat "${baseline_dir}/register.response" >&2 || true
  echo "baseline Spring Data Commons form payload did not reach the server" >&2
  exit 1
fi
if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
  cat "${baseline_dir}/register.response" >&2 || true
  echo "baseline Spring Data Commons did not create ${success_file}" >&2
  exit 1
fi

protected_status="$(
  send_form_payload "$protected_port" "$protected_body" "${protected_dir}/register.response"
)"
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/register.response" >&2 || true
  echo "protected Spring Data Commons form payload did not reach the server" >&2
  exit 1
fi
if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
  echo "protected Spring Data Commons created ${success_file} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Spring Data Commons CVE-2018-1273" >&2
  exit 1
fi

echo "vulhub Spring Data Commons CVE-2018-1273 Java8 acceptance passed"
