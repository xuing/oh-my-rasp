#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

image="${OHMYRASP_VULHUB_JENKINS_23897_IMAGE:-vulhub/jenkins:2.441}"
baseline_name="${OHMYRASP_VULHUB_JENKINS_23897_BASELINE_NAME:-ohmyrasp-vulhub-jenkins-23897-baseline}"
protected_name="${OHMYRASP_VULHUB_JENKINS_23897_PROTECTED_NAME:-ohmyrasp-vulhub-jenkins-23897-protected}"
baseline_port="${OHMYRASP_VULHUB_JENKINS_23897_BASELINE_PORT:-19144}"
protected_port="${OHMYRASP_VULHUB_JENKINS_23897_PROTECTED_PORT:-19145}"
baseline_dir="logs/vulhub-jenkins-2024-23897-java17-baseline"
protected_dir="logs/vulhub-jenkins-2024-23897-java17-protected"
protected_log="${protected_dir}/events.jsonl"
cli_dir="${baseline_dir}/cli"

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
  echo "Jenkins CVE-2024-23897 did not become ready at ${port}" >&2
  exit 1
}

run_cli_file_read() {
  local port="$1"
  local output="$2"
  local status
  set +e
  docker run --rm --network host -v "$(pwd)/${cli_dir}:/work" -w /work \
    gradle:jdk25 \
    java -jar jenkins-cli.jar -s "http://127.0.0.1:${port}/" -http \
      connect-node '@/etc/passwd' > "$output" 2>&1
  status=$?
  set -e
  printf '%s\n' "$status"
}

expect_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2 || true
    echo "missing Java 17 startup event for Jenkins CVE-2024-23897" >&2
    exit 1
  fi
  if ! grep -q '"file_hook":"installed"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2
    echo "missing Java 17 file hook startup marker for Jenkins CVE-2024-23897" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    sed -n '1,160p' "$protected_log" >&2
    echo "Jenkins CVE-2024-23897 produced a detection before the CLI exploit" >&2
    exit 1
  fi
}

wait_for_file_read_block() {
  for attempt in $(seq 1 30); do
    printf 'file_read_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if grep -Eq '"algorithm":"java17_file_sensitive_read".*"action":"block"' \
      "$protected_log" 2>/dev/null; then
      return
    fi
    sleep 1
  done
  sed -n '1,200p' "$protected_log" >&2 || true
  echo "missing java17_file_sensitive_read block event for Jenkins CVE-2024-23897" >&2
  exit 1
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$cli_dir"
rm -f "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --init --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  -e DEBUG=1 \
  "$image" >/dev/null

wait_for_jenkins "$baseline_name" "$baseline_port" "$baseline_dir"
curl -fsS -o "${cli_dir}/jenkins-cli.jar" \
  "http://127.0.0.1:${baseline_port}/jnlpJars/jenkins-cli.jar"
baseline_status="$(run_cli_file_read "$baseline_port" "${baseline_dir}/connect-node-passwd.response")"
printf 'baseline_cli_status=%s\n' "$baseline_status" >> "${baseline_dir}/attempts.log"
if ! grep -Eq 'root:.*:0:0:' "${baseline_dir}/connect-node-passwd.response"; then
  sed -n '1,160p' "${baseline_dir}/connect-node-passwd.response" >&2 || true
  echo "Jenkins CVE-2024-23897 baseline did not disclose /etc/passwd" >&2
  exit 1
fi

docker run -d --init --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e DEBUG=1 \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
  "$image" >/dev/null

wait_for_jenkins "$protected_name" "$protected_port" "$protected_dir"
expect_startup_without_detection
protected_status="$(run_cli_file_read "$protected_port" "${protected_dir}/connect-node-passwd.response")"
printf 'protected_cli_status=%s\n' "$protected_status" >> "${protected_dir}/attempts.log"
if grep -Eq 'root:.*:0:0:' "${protected_dir}/connect-node-passwd.response"; then
  sed -n '1,160p' "${protected_dir}/connect-node-passwd.response" >&2
  echo "Jenkins CVE-2024-23897 protected CLI disclosed /etc/passwd" >&2
  exit 1
fi
wait_for_file_read_block

echo "vulhub Jenkins CVE-2024-23897 Java17 acceptance passed"
