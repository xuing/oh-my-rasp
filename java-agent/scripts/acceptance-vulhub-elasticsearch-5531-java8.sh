#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

vulhub_context="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_CONTEXT:-/tmp/vulhub-ohmyrasp-20260603/elasticsearch/CVE-2015-5531}"
image="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_IMAGE:-ohmyrasp/vulhub-elasticsearch:5531}"
baseline_name="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_BASELINE_NAME:-ohmyrasp-vulhub-elasticsearch-5531-baseline}"
protected_name="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_PROTECTED_NAME:-ohmyrasp-vulhub-elasticsearch-5531-protected}"
baseline_port="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_BASELINE_PORT:-18584}"
protected_port="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_PROTECTED_PORT:-18585}"
baseline_cluster="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_BASELINE_CLUSTER:-ohmyrasp-es5531-baseline}"
protected_cluster="${OHMYRASP_VULHUB_ELASTICSEARCH_5531_PROTECTED_CLUSTER:-ohmyrasp-es5531-protected}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-elasticsearch-5531-java8-baseline"
protected_dir="logs/vulhub-elasticsearch-5531-java8-protected"
protected_log="${protected_dir}/events.jsonl"
traversal_path="/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

if [[ ! -d "$vulhub_context" ]]; then
  echo "missing Vulhub Elasticsearch CVE-2015-5531 context: ${vulhub_context}" >&2
  exit 1
fi
docker build -t "$image" "$vulhub_context"

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

docker run -d --name "$baseline_name" -p "127.0.0.1:${baseline_port}:9200" \
  "$image" elasticsearch -Des.cluster.name="$baseline_cluster" >/dev/null

docker run -d --name "$protected_name" -p "127.0.0.1:${protected_port}:9200" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" elasticsearch -Des.cluster.name="$protected_cluster" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q '"number" : "1.6.0"' "$output"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Elasticsearch 1.6.0 at ${port}" >&2
  exit 1
}

put_repository() {
  local port="$1"
  local repository="$2"
  local location="$3"
  local output="$4"
  curl -sS -XPUT -H "Content-Type: application/json" \
    --data-binary "{\"type\":\"fs\",\"settings\":{\"location\":\"${location}\"}}" \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/_snapshot/${repository}" || true
}

read_passwd() {
  local port="$1"
  local output="$2"
  curl -sS --path-as-is -i -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}${traversal_path}" || true
}

wait_for "$baseline_name" "$baseline_port" "${baseline_dir}/ready.response"
wait_for "$protected_name" "$protected_port" "${protected_dir}/ready.response"

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Elasticsearch CVE-2015-5531 protected container" >&2
  exit 1
fi
if ! grep -q '"file_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing Java 8 file hook marker in Elasticsearch CVE-2015-5531 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Elasticsearch CVE-2015-5531 protected startup/readiness produced a detection before setup" >&2
  exit 1
fi

for side in baseline protected; do
  if [[ "$side" == "baseline" ]]; then
    port="$baseline_port"
    dir="$baseline_dir"
  else
    port="$protected_port"
    dir="$protected_dir"
  fi
  repo_status="$(put_repository "$port" test "/usr/share/elasticsearch/repo/test" "${dir}/repo-test.response")"
  repo2_status="$(put_repository "$port" test2 "/usr/share/elasticsearch/repo/test/snapshot-backdata" "${dir}/repo-test2.response")"
  if [[ "$repo_status" != "200" || "$repo2_status" != "200" ]] \
      || ! grep -q '"acknowledged":true' "${dir}/repo-test.response" \
      || ! grep -q '"acknowledged":true' "${dir}/repo-test2.response"; then
    cat "${dir}/repo-test.response" >&2 || true
    cat "${dir}/repo-test2.response" >&2 || true
    echo "Elasticsearch CVE-2015-5531 ${side} snapshot repository setup failed" >&2
    exit 1
  fi
done
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Elasticsearch CVE-2015-5531 protected repository setup produced a detection before exploit traffic" >&2
  exit 1
fi

baseline_status="$(read_passwd "$baseline_port" "${baseline_dir}/attack.response")"
if [[ "$baseline_status" != "400" ]] \
    || ! grep -q 'Failed to derive xcontent' "${baseline_dir}/attack.response" \
    || ! grep -q '114, 111, 111, 116, 58, 120, 58, 48, 58, 48' "${baseline_dir}/attack.response" \
    || ! grep -q '100, 97, 101, 109, 111, 110, 58, 120' "${baseline_dir}/attack.response"; then
  sed -n '1,180p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Elasticsearch CVE-2015-5531 traversal did not disclose /etc/passwd bytes; status=${baseline_status}" >&2
  exit 1
fi

protected_status="$(read_passwd "$protected_port" "${protected_dir}/attack.response")"
if [[ "$protected_status" == "000" ]] \
    || grep -q '114, 111, 111, 116, 58, 120, 58, 48, 58, 48' "${protected_dir}/attack.response"; then
  sed -n '1,180p' "${protected_dir}/attack.response" >&2 || true
  echo "protected Elasticsearch CVE-2015-5531 traversal was not blocked before passwd disclosure; status=${protected_status}" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_file_sensitive_read".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_file_sensitive_read block event for Elasticsearch CVE-2015-5531" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/attack.response"; then
  sed -n '1,180p' "${protected_dir}/attack.response" >&2 || true
  echo "missing Java8RaspBlockException evidence for protected Elasticsearch CVE-2015-5531" >&2
  exit 1
fi

echo "vulhub Elasticsearch CVE-2015-5531 Java8 acceptance passed"
