#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_SOLR0193_BASELINE_NAME:-ohmyrasp-vulhub-solr0193-baseline}"
protected_name="${OHMYRASP_VULHUB_SOLR0193_PROTECTED_NAME:-ohmyrasp-vulhub-solr0193-protected}"
baseline_port="${OHMYRASP_VULHUB_SOLR0193_BASELINE_PORT:-18790}"
protected_port="${OHMYRASP_VULHUB_SOLR0193_PROTECTED_PORT:-18791}"
image="${OHMYRASP_VULHUB_SOLR0193_IMAGE:-vulhub/solr:8.1.1}"
marker="/tmp/ohmyrasp-solr0193-success"
baseline_dir="logs/vulhub-solr-2019-0193-java8-baseline"
protected_dir="logs/vulhub-solr-2019-0193-java8-protected"
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
    status="$(curl -sS -o "/tmp/${name}.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/solr/admin/cores?indexInfo=false&wt=json" \
      2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q '"demo"' "/tmp/${name}.json"; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose Solr demo core at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected Solr container" >&2
    exit 1
  fi
  if ! grep -q '"script_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 script hook startup marker in protected Solr container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Solr container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

dataimport_config() {
  cat <<XML
<dataConfig>
  <script><![CDATA[
          function poc(){ java.lang.Runtime.getRuntime().exec("touch ${marker}");
          }
  ]]></script>
  <document>
    <entity name="sample"
            fileName=".*"
            baseDir="/"
            processor="FileListEntityProcessor"
            recursive="false"
            transformer="script:poc" />
  </document>
</dataConfig>
XML
}

send_dataimport_payload() {
  local port="$1"
  local output="$2"
  local data_config
  data_config="$(dataimport_config)"
  curl -sS -i -H 'Content-Type: application/x-www-form-urlencoded' \
    -o "$output" -w "%{http_code}" \
    --data-urlencode 'command=full-import' \
    --data-urlencode 'verbose=false' \
    --data-urlencode 'clean=false' \
    --data-urlencode 'commit=true' \
    --data-urlencode 'debug=true' \
    --data-urlencode 'core=demo' \
    --data-urlencode "dataConfig=${data_config}" \
    --data-urlencode 'name=dataimport' \
    "http://127.0.0.1:${port}/solr/demo/dataimport?_=1708782956647&indent=on&wt=json" || true
}

marker_state() {
  local name="$1"
  docker exec "$name" sh -lc "test -f '$marker' && echo present || echo missing" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8983" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8983" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "SOLR_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"
expect_protected_startup_without_detection

baseline_status="$(send_dataimport_payload "$baseline_port" "${baseline_dir}/dataimport.response")"
if [[ "$baseline_status" == "000" ]]; then
  cat "${baseline_dir}/dataimport.response" >&2 || true
  echo "baseline Solr DataImportHandler request did not reach the HTTP endpoint" >&2
  exit 1
fi
sleep 2
if [[ "$(marker_state "$baseline_name")" != "present" ]]; then
  cat "${baseline_dir}/dataimport.response" >&2 || true
  echo "baseline Solr DataImportHandler payload did not create ${marker}" >&2
  exit 1
fi

protected_status="$(send_dataimport_payload "$protected_port" "${protected_dir}/dataimport.response")"
if [[ "$protected_status" == "000" ]]; then
  cat "${protected_dir}/dataimport.response" >&2 || true
  echo "protected Solr DataImportHandler request did not reach the HTTP endpoint" >&2
  exit 1
fi
sleep 2
if [[ "$(marker_state "$protected_name")" != "missing" ]]; then
  cat "$protected_log" >&2 || true
  echo "protected Solr DataImportHandler still created ${marker}" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_script_engine_runtime_execution".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_script_engine_runtime_execution block event for Solr DataImportHandler RCE" >&2
  exit 1
fi
if ! grep -q '"Full Import failed"' "${protected_dir}/dataimport.response"; then
  cat "${protected_dir}/dataimport.response" >&2 || true
  echo "protected Solr DataImportHandler response did not report a failed import" >&2
  exit 1
fi

echo "vulhub Solr CVE-2019-0193 DataImportHandler Java8 acceptance passed"
