#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_SOLR_REMOTESTREAM_BASELINE_NAME:-ohmyrasp-vulhub-solr-remotestream-baseline}"
protected_name="${OHMYRASP_VULHUB_SOLR_REMOTESTREAM_PROTECTED_NAME:-ohmyrasp-vulhub-solr-remotestream-protected}"
baseline_port="${OHMYRASP_VULHUB_SOLR_REMOTESTREAM_BASELINE_PORT:-18788}"
protected_port="${OHMYRASP_VULHUB_SOLR_REMOTESTREAM_PROTECTED_PORT:-18789}"
image="${OHMYRASP_VULHUB_SOLR_REMOTESTREAM_IMAGE:-vulhub/solr:8.8.1}"
baseline_dir="logs/vulhub-solr-remotestreaming-java8-baseline"
protected_dir="logs/vulhub-solr-remotestreaming-java8-protected"
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
  if ! grep -q '"file_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 file hook startup marker in protected Solr container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Solr container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

enable_remote_streaming() {
  local port="$1"
  local output="$2"
  local body
  body='{"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'
  curl -sS -i -H 'Content-Type: application/json' --data "$body" \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/solr/demo/config" || true
}

read_passwd_stream() {
  local port="$1"
  local output="$2"
  curl -sS -i -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/solr/demo/debug/dump?param=ContentStreams&stream.url=file:///etc/passwd" || true
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

baseline_config_status="$(
  enable_remote_streaming "$baseline_port" "${baseline_dir}/config.response"
)"
protected_config_status="$(
  enable_remote_streaming "$protected_port" "${protected_dir}/config.response"
)"
if [[ "$baseline_config_status" != "200" ]] || [[ "$protected_config_status" != "200" ]]; then
  cat "${baseline_dir}/config.response" >&2 || true
  cat "${protected_dir}/config.response" >&2 || true
  echo "Solr RemoteStreaming config API did not return 200" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected Solr container produced a detection during benign RemoteStreaming config" >&2
  exit 1
fi

baseline_status="$(read_passwd_stream "$baseline_port" "${baseline_dir}/stream.response")"
if [[ "$baseline_status" == "000" ]] \
    || ! grep -q 'root:x:0:0:' "${baseline_dir}/stream.response" \
    || ! grep -q 'daemon:x:' "${baseline_dir}/stream.response"; then
  cat "${baseline_dir}/stream.response" >&2 || true
  echo "baseline Solr RemoteStreaming request did not disclose /etc/passwd" >&2
  exit 1
fi

protected_status="$(read_passwd_stream "$protected_port" "${protected_dir}/stream.response")"
if [[ "$protected_status" == "000" ]] \
    || grep -q 'root:x:0:0:' "${protected_dir}/stream.response"; then
  cat "${protected_dir}/stream.response" >&2 || true
  echo "protected Solr RemoteStreaming request was not blocked before passwd disclosure" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_file_sensitive_read".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_file_sensitive_read block event for Solr RemoteStreaming file read" >&2
  exit 1
fi
if ! grep -q 'Java8RaspBlockException' "${protected_dir}/stream.response" "$protected_log"; then
  cat "${protected_dir}/stream.response" >&2 || true
  cat "$protected_log" >&2
  echo "missing Java8RaspBlockException evidence for protected Solr RemoteStreaming file read" >&2
  exit 1
fi

echo "vulhub Solr RemoteStreaming file read Java8 acceptance passed"
