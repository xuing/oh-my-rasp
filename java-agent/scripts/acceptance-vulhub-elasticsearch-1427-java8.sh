#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_ELASTICSEARCH_1427_IMAGE:-vulhub/elasticsearch:1.4.2}"
baseline_name="${OHMYRASP_VULHUB_ELASTICSEARCH_1427_BASELINE_NAME:-ohmyrasp-vulhub-elasticsearch-1427-baseline}"
protected_name="${OHMYRASP_VULHUB_ELASTICSEARCH_1427_PROTECTED_NAME:-ohmyrasp-vulhub-elasticsearch-1427-protected}"
baseline_port="${OHMYRASP_VULHUB_ELASTICSEARCH_1427_BASELINE_PORT:-18578}"
protected_port="${OHMYRASP_VULHUB_ELASTICSEARCH_1427_PROTECTED_PORT:-18579}"
baseline_cluster="${OHMYRASP_VULHUB_ELASTICSEARCH_1427_BASELINE_CLUSTER:-ohmyrasp-es1427-baseline}"
protected_cluster="${OHMYRASP_VULHUB_ELASTICSEARCH_1427_PROTECTED_CLUSTER:-ohmyrasp-es1427-protected}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-elasticsearch-1427-java8-baseline"
protected_dir="logs/vulhub-elasticsearch-1427-java8-protected"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-es-1427-success"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:9200" \
  "$image" elasticsearch -Des.cluster.name="$baseline_cluster" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:9200" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" elasticsearch -Des.cluster.name="$protected_cluster" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Elasticsearch 1.4.2 root at ${port}" >&2
  exit 1
}

index_document() {
  local port="$1"
  local output="$2"
  local status
  status="$(curl -sS -XPOST -H "Content-Type: application/json" \
    --data-binary '{"name":"ohmyrasp"}' \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/website/blog/" || true)"
  if [[ "$status" != "201" && "$status" != "200" ]]; then
    sed -n '1,120p' "$output" >&2 || true
    echo "Elasticsearch index request failed on ${port}; status=${status}" >&2
    exit 1
  fi
  curl -sS -XPOST "http://127.0.0.1:${port}/_refresh" >/dev/null
}

run_attack() {
  local port="$1"
  local output="$2"
  python3 - "$port" "$output" "$marker" <<'PY'
import http.client
import json
import sys

port = int(sys.argv[1])
output = sys.argv[2]
marker = sys.argv[3]
body = json.dumps(
    {
        "size": 1,
        "script_fields": {
            "lupin": {
                "lang": "groovy",
                "script": (
                    'java.lang.Math.class.forName("java.lang.Runtime")'
                    f'.getRuntime().exec("touch {marker}").getText()'
                ),
            }
        },
    }
).encode()
headers = {
    "Content-Type": "application/json",
    "Content-Length": str(len(body)),
    "User-Agent": "ohmyrasp-es-1427",
}
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
try:
    connection.request("POST", "/_search?pretty", body=body, headers=headers)
    response = connection.getresponse()
    content = response.read()
finally:
    connection.close()

with open(output, "wb") as handle:
    handle.write(f"HTTP/1.1 {response.status} {response.reason}\n".encode())
    for key, value in response.getheaders():
        handle.write(f"{key}: {value}\n".encode(errors="replace"))
    handle.write(b"\n")
    handle.write(content)
print(response.status)
PY
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

docker exec "$baseline_name" rm -f "$marker" >/dev/null
docker exec "$protected_name" rm -f "$marker" >/dev/null

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Elasticsearch CVE-2015-1427 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Elasticsearch CVE-2015-1427 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

index_document "$baseline_port" "${baseline_dir}/index.response"
index_document "$protected_port" "${protected_dir}/index.response"
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Elasticsearch CVE-2015-1427 protected indexing produced a detection before the exploit request" >&2
  exit 1
fi

baseline_status="$(run_attack "$baseline_port" "${baseline_dir}/attack.response")"
if [[ "$baseline_status" != "200" ]] || ! docker exec "$baseline_name" test -e "$marker"; then
  sed -n '1,220p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Elasticsearch CVE-2015-1427 Groovy payload did not create ${marker}; status=${baseline_status}" >&2
  exit 1
fi

protected_status="$(run_attack "$protected_port" "${protected_dir}/attack.response")"
if [[ "$protected_status" != "200" ]]; then
  sed -n '1,220p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Elasticsearch CVE-2015-1427 did not return a search response; status=${protected_status}" >&2
  exit 1
fi
if docker exec "$protected_name" test -e "$marker"; then
  echo "protected Elasticsearch CVE-2015-1427 created ${marker} despite Java8 RASP; status=${protected_status}" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/attack.response"; then
  sed -n '1,220p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Elasticsearch CVE-2015-1427 response did not expose the blocked shard failure; status=${protected_status}" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    echo "vulhub Elasticsearch CVE-2015-1427 Java8 acceptance passed"
    exit 0
  fi
  sleep 1
done

cat "$protected_log" >&2
echo "missing java8_command_execution_exploit_primitive block event for Elasticsearch CVE-2015-1427" >&2
exit 1
