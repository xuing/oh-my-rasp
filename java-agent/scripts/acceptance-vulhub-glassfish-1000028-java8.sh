#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_GLASSFISH_1000028_IMAGE:-vulhub/glassfish:4.1}"
baseline_name="${OHMYRASP_VULHUB_GLASSFISH_1000028_BASELINE_NAME:-ohmyrasp-vulhub-glassfish-1000028-baseline}"
protected_name="${OHMYRASP_VULHUB_GLASSFISH_1000028_PROTECTED_NAME:-ohmyrasp-vulhub-glassfish-1000028-protected}"
baseline_port="${OHMYRASP_VULHUB_GLASSFISH_1000028_BASELINE_PORT:-18610}"
protected_port="${OHMYRASP_VULHUB_GLASSFISH_1000028_PROTECTED_PORT:-18611}"
admin_password="${OHMYRASP_VULHUB_GLASSFISH_1000028_ADMIN_PASSWORD:-vulhub_default_password}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-glassfish-1000028-java8-baseline"
protected_dir="logs/vulhub-glassfish-1000028-java8-protected"
protected_log="${protected_dir}/events.jsonl"
traversal_path="/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "127.0.0.1:${baseline_port}:4848" \
  -e "ADMIN_PASSWORD=${admin_password}" \
  -e "JAVA_DEBUGGER_PORT=5005" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "127.0.0.1:${protected_port}:4848" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "ADMIN_PASSWORD=${admin_password}" \
  -e "JAVA_DEBUGGER_PORT=5005" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_glassfish() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl -ksS -o "$output" -w "%{http_code}" \
      "https://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -Eq 'GlassFish|Login|login' "$output"; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
        | grep -q .; then
      docker logs "$name" >&2 || true
      echo "${name} exited before exposing GlassFish admin at ${port}" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose GlassFish admin at ${port}" >&2
  exit 1
}

read_passwd() {
  local port="$1"
  local output="$2"
  curl -ksS --path-as-is -i -o "$output" -w "%{http_code}" \
    "https://127.0.0.1:${port}${traversal_path}" || true
}

wait_for_glassfish "$baseline_name" "$baseline_port" "${baseline_dir}/ready.response"
wait_for_glassfish "$protected_name" "$protected_port" "${protected_dir}/ready.response"

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in GlassFish CVE-2017-1000028 protected container" >&2
  exit 1
fi
if ! grep -q '"request_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing Java 8 request hook marker in GlassFish CVE-2017-1000028 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "GlassFish CVE-2017-1000028 protected startup/readiness produced a detection before exploit traffic" >&2
  exit 1
fi

baseline_status="$(read_passwd "$baseline_port" "${baseline_dir}/attack.response")"
if [[ "$baseline_status" != "200" ]] \
    || ! grep -q 'root:x:0:0:' "${baseline_dir}/attack.response" \
    || ! grep -q 'daemon:x:' "${baseline_dir}/attack.response"; then
  sed -n '1,160p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline GlassFish CVE-2017-1000028 traversal did not disclose /etc/passwd; status=${baseline_status}" >&2
  exit 1
fi

protected_status="$(read_passwd "$protected_port" "${protected_dir}/attack.response")"
if [[ "$protected_status" == "000" ]] \
    || grep -q 'root:x:0:0:' "${protected_dir}/attack.response"; then
  sed -n '1,160p' "${protected_dir}/attack.response" >&2 || true
  echo "protected GlassFish CVE-2017-1000028 traversal was not blocked before passwd disclosure; status=${protected_status}" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_request_path_confusion".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_request_path_confusion block event for GlassFish CVE-2017-1000028" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/attack.response"; then
  sed -n '1,160p' "${protected_dir}/attack.response" >&2 || true
  echo "missing Java8RaspBlockException evidence for protected GlassFish CVE-2017-1000028" >&2
  exit 1
fi

echo "vulhub GlassFish CVE-2017-1000028 Java8 acceptance passed"
