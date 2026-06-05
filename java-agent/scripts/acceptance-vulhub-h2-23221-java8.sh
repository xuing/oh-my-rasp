#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_H2_23221_BASELINE_NAME:-ohmyrasp-vulhub-h2-23221-baseline}"
protected_name="${OHMYRASP_VULHUB_H2_23221_PROTECTED_NAME:-ohmyrasp-vulhub-h2-23221-protected}"
baseline_port="${OHMYRASP_VULHUB_H2_23221_BASELINE_PORT:-18792}"
protected_port="${OHMYRASP_VULHUB_H2_23221_PROTECTED_PORT:-18793}"
image="${OHMYRASP_VULHUB_H2_23221_IMAGE:-vulhub/spring-with-h2database:2.0.206}"
baseline_dir="logs/vulhub-h2-2022-23221-java8-baseline"
protected_dir="logs/vulhub-h2-2022-23221-java8-protected"
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
  if ! grep -q '"jdbc_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 JDBC hook startup marker in protected H2 container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected H2 container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

h2_payload() {
  cat <<'PAYLOAD'
jdbc:h2:mem:test;MODE=MSSQLServer;FORBID_CREATION=FALSE;INIT=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
    var is = java.lang.Runtime.getRuntime().exec("id").getInputStream()
    var scanner = new java.util.Scanner(is).useDelimiter("\\A")
    throw new java.lang.Exception(scanner.next())
$$;AUTHZPWD=\
PAYLOAD
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

send_h2_payload() {
  local port="$1"
  local output="$2"
  local dir="$3"
  local jsessionid
  local payload
  jsessionid="$(h2_session "$port" "$dir")"
  payload="$(h2_payload)"
  curl -sS -i -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'language=en' \
    --data-urlencode 'setting=Generic H2 (Embedded)' \
    --data-urlencode 'name=Generic H2 (Embedded)' \
    --data-urlencode 'driver=org.h2.Driver' \
    --data-urlencode "url=${payload}" \
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
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_status="$(send_h2_payload "$baseline_port" "${baseline_dir}/login.response" "$baseline_dir")"
if [[ "$baseline_status" == "000" ]] \
    || ! grep -q 'uid=0(root)' "${baseline_dir}/login.response"; then
  cat "${baseline_dir}/login.response" >&2 || true
  echo "baseline H2 CVE-2022-23221 login payload did not execute id" >&2
  exit 1
fi

protected_status="$(send_h2_payload "$protected_port" "${protected_dir}/login.response" "$protected_dir")"
if [[ "$protected_status" == "000" ]] \
    || grep -q 'uid=0(root)' "${protected_dir}/login.response"; then
  cat "${protected_dir}/login.response" >&2 || true
  echo "protected H2 CVE-2022-23221 login payload was not blocked before command output" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_jdbc_h2_code_execution".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_jdbc_h2_code_execution block event for H2 CVE-2022-23221" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/login.response" "$protected_log"; then
  cat "${protected_dir}/login.response" >&2 || true
  cat "$protected_log" >&2
  echo "missing Java8RaspBlockException evidence for protected H2 CVE-2022-23221" >&2
  exit 1
fi

echo "vulhub H2 CVE-2022-23221 Java8 acceptance passed"
