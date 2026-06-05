#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_HUGEGRAPH_IMAGE:-vulhub/hugegraph:1.2.0}"
baseline_name="${OHMYRASP_VULHUB_HUGEGRAPH_BASELINE_NAME:-ohmyrasp-vulhub-hugegraph27348-baseline}"
protected_name="${OHMYRASP_VULHUB_HUGEGRAPH_PROTECTED_NAME:-ohmyrasp-vulhub-hugegraph27348-protected}"
baseline_port="${OHMYRASP_VULHUB_HUGEGRAPH_BASELINE_PORT:-18420}"
protected_port="${OHMYRASP_VULHUB_HUGEGRAPH_PROTECTED_PORT:-18421}"
host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"
baseline_dir="logs/vulhub-hugegraph-1.2.0-java11-baseline"
protected_dir="logs/vulhub-hugegraph-1.2.0-java11-protected"
protected_log="${protected_dir}/events.jsonl"
success_file="/tmp/ohmyrasp-hugegraph-success"
payload_file="${baseline_dir}/gremlin-processbuilder.json"
ready_file="${baseline_dir}/gremlin-ready.json"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

python3 - "$payload_file" "$ready_file" <<'PY'
import json
import sys

payload = {
    "gremlin": (
        'Thread thread = Thread.currentThread();'
        'Class clz = Class.forName("java.lang.Thread");'
        'java.lang.reflect.Field field = clz.getDeclaredField("name");'
        'field.setAccessible(true);'
        'field.set(thread, "SL7");'
        'Class processBuilderClass = Class.forName("java.lang.ProcessBuilder");'
        'java.lang.reflect.Constructor constructor = processBuilderClass.getConstructor(java.util.List.class);'
        'java.util.List command = java.util.Arrays.asList("sh","-c","cat /etc/passwd > /tmp/ohmyrasp-hugegraph-success");'
        'Object processBuilderInstance = constructor.newInstance(command);'
        'java.lang.reflect.Method startMethod = processBuilderClass.getMethod("start");'
        'Object process = startMethod.invoke(processBuilderInstance);'
        'process.waitFor();'
        '"ok";'
    ),
    "bindings": {},
    "language": "gremlin-groovy",
    "aliases": {},
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump({"gremlin": "1+1", "bindings": {}, "language": "gremlin-groovy", "aliases": {}}, handle)
PY

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/versions" || true)"
    if [[ "$status" == "200" ]]; then
      status="$(curl -sS -o "/tmp/${name}-gremlin-ready.json" -w "%{http_code}" \
        -H 'Content-Type: application/json' \
        --data-binary "@${ready_file}" \
        "http://127.0.0.1:${port}/gremlin" || true)"
    fi
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose HugeGraph at ${port}" >&2
  exit 1
}

post_gremlin() {
  local port="$1"
  local output="$2"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${payload_file}" \
    "http://127.0.0.1:${port}/gremlin" || true
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 11 startup event in HugeGraph protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "HugeGraph protected startup produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(post_gremlin "$baseline_port" "${baseline_dir}/gremlin-processbuilder.response")"
if [[ "$baseline_status" != "200" ]] || ! docker exec "$baseline_name" test -s "$success_file"; then
  cat "${baseline_dir}/gremlin-processbuilder.response" >&2 || true
  echo "baseline HugeGraph did not execute the Gremlin ProcessBuilder payload" >&2
  exit 1
fi

protected_status="$(post_gremlin "$protected_port" "${protected_dir}/gremlin-processbuilder.response")"
if [[ "$protected_status" != "500" ]]; then
  cat "${protected_dir}/gremlin-processbuilder.response" >&2 || true
  echo "protected HugeGraph returned unexpected status ${protected_status}" >&2
  exit 1
fi
if docker exec "$protected_name" test -e "$success_file"; then
  echo "protected HugeGraph created ${success_file} despite Java11 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java11_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java11_command_execution_exploit_primitive block event for HugeGraph CVE-2024-27348" >&2
  exit 1
fi

echo "vulhub HugeGraph 1.2.0 CVE-2024-27348 Java11 acceptance passed"
