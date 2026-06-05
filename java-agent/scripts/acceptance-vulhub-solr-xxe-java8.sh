#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_SOLR12629_XXE_BASELINE_NAME:-ohmyrasp-vulhub-solr12629-xxe-baseline}"
protected_name="${OHMYRASP_VULHUB_SOLR12629_XXE_PROTECTED_NAME:-ohmyrasp-vulhub-solr12629-xxe-protected}"
baseline_port="${OHMYRASP_VULHUB_SOLR12629_XXE_BASELINE_PORT:-18786}"
protected_port="${OHMYRASP_VULHUB_SOLR12629_XXE_PROTECTED_PORT:-18787}"
image="${OHMYRASP_VULHUB_SOLR12629_XXE_IMAGE:-vulhub/solr:7.0.1}"
baseline_dir="logs/vulhub-solr-2017-12629-xxe-java8-baseline"
protected_dir="logs/vulhub-solr-2017-12629-xxe-java8-protected"
protected_log="${protected_dir}/events.jsonl"
payload_file="$(pwd)/${baseline_dir}/xxe-payload.xml"

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
  if ! grep -q '"xxe_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 XXE hook startup marker in protected Solr container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Solr container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

write_xxe_payload() {
  cat > "$payload_file" <<'XML'
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "jar:file:///opt/solr/server/solr-webapp/webapp/WEB-INF/lib/lucene-queryparser-7.0.1.jar!/org/apache/lucene/queryparser/xml/LuceneCoreQuery.dtd">

    <!ENTITY % queries 'aaa)>
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ELEMENT aa (bb'>

    %local_dtd;
]>
<message>any text</message>
XML
}

send_xxe_payload() {
  local port="$1"
  local output="$2"
  curl -sS -i -G -o "$output" -w "%{http_code}" \
    --data-urlencode 'wt=xml' \
    --data-urlencode 'defType=xmlparser' \
    --data-urlencode "q@${payload_file}" \
    "http://127.0.0.1:${port}/solr/demo/select" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
write_xxe_payload

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

baseline_status="$(send_xxe_payload "$baseline_port" "${baseline_dir}/xxe.response")"
if [[ "$baseline_status" == "000" ]] \
    || ! grep -q 'root:x:0:0:' "${baseline_dir}/xxe.response" \
    || ! grep -q 'daemon:x:' "${baseline_dir}/xxe.response"; then
  cat "${baseline_dir}/xxe.response" >&2 || true
  echo "baseline Solr XML parser payload did not disclose /etc/passwd through XXE" >&2
  exit 1
fi

protected_status="$(send_xxe_payload "$protected_port" "${protected_dir}/xxe.response")"
if [[ "$protected_status" == "000" ]] \
    || grep -q 'root:x:0:0:' "${protected_dir}/xxe.response"; then
  cat "${protected_dir}/xxe.response" >&2 || true
  echo "protected Solr XML parser payload was not blocked before passwd disclosure" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_xxe_external_entity_protocol".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_xxe_external_entity_protocol block event for Solr XML parser XXE" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/xxe.response" "$protected_log"; then
  cat "${protected_dir}/xxe.response" >&2 || true
  cat "$protected_log" >&2
  echo "missing Java8RaspBlockException evidence for protected Solr XML parser XXE" >&2
  exit 1
fi

echo "vulhub Solr CVE-2017-12629 XML parser XXE Java8 acceptance passed"
