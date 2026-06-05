#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_CXF_IMAGE:-vulhub/apache-cxf:3.2.14}"
baseline_name="${OHMYRASP_VULHUB_CXF_BASELINE_NAME:-ohmyrasp-vulhub-cxf-28752-baseline}"
protected_name="${OHMYRASP_VULHUB_CXF_PROTECTED_NAME:-ohmyrasp-vulhub-cxf-28752-protected}"
baseline_port="${OHMYRASP_VULHUB_CXF_BASELINE_PORT:-19082}"
protected_port="${OHMYRASP_VULHUB_CXF_PROTECTED_PORT:-19083}"
baseline_dir="logs/vulhub-cxf-2024-28752-java8-baseline"
protected_dir="logs/vulhub-cxf-2024-28752-java8-protected"
protected_log="${protected_dir}/events.jsonl"
hosts_base64_prefix="MTI3LjAuMC4xCWxvY2FsaG9zdA"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_payload() {
  local output="$1"
  cat > "$output" <<'SOAP'
------kkkkkk123123213
Content-Disposition: form-data; name="1"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://service.namespace/">
   <soapenv:Header/>
   <soapenv:Body>
      <web:test>
         <arg0>
<count><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/hosts"></xop:Include></count>
</arg0>
      </web:test>
   </soapenv:Body>
</soapenv:Envelope>
------kkkkkk123123213--
SOAP
}

wait_for_wsdl() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl --max-time 5 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/test?wsdl" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "CXF did not expose /test?wsdl at ${port}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java8 agent startup event for CXF protected container" >&2
  exit 1
}

post_payload() {
  local port="$1"
  local payload="$2"
  local output="$3"
  local status
  status="$(
    curl --max-time 20 -sS -i -o "$output" -w "%{http_code}" \
      -X POST \
      -H 'Content-Type: multipart/related; boundary=----kkkkkk123123213' \
      --data-binary "@${payload}" \
      "http://127.0.0.1:${port}/test" 2>/dev/null || true
  )"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf '%s' "$status"
}

run_baseline() {
  local payload="${baseline_dir}/cxf-xop-file-hosts.request"
  local status
  write_payload "$payload"
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8080" \
    "$image" >/dev/null

  wait_for_wsdl "$baseline_name" "$baseline_port" "$baseline_dir"
  status="$(post_payload "$baseline_port" "$payload" "${baseline_dir}/cxf-xop-file-hosts.response")"
  printf 'baseline_payload_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" == "000" ]]; then
    cat "${baseline_dir}/cxf-xop-file-hosts.response" >&2 || true
    echo "baseline CXF payload did not reach the HTTP endpoint" >&2
    exit 1
  fi
  if ! grep -Fq "$hosts_base64_prefix" "${baseline_dir}/cxf-xop-file-hosts.response"; then
    cat "${baseline_dir}/cxf-xop-file-hosts.response" >&2 || true
    echo "baseline CXF did not disclose /etc/hosts through the XOP file reference" >&2
    exit 1
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  local payload="${protected_dir}/cxf-xop-file-hosts.request"
  local status
  write_payload "$payload"
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8080" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_wsdl "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "CXF protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  status="$(post_payload "$protected_port" "$payload" "${protected_dir}/cxf-xop-file-hosts.response")"
  printf 'protected_payload_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if [[ "$status" == "000" ]]; then
    cat "${protected_dir}/cxf-xop-file-hosts.response" >&2 || true
    echo "protected CXF payload did not reach the HTTP endpoint" >&2
    exit 1
  fi
  if grep -Fq "$hosts_base64_prefix" "${protected_dir}/cxf-xop-file-hosts.response"; then
    cat "${protected_dir}/cxf-xop-file-hosts.response" >&2 || true
    echo "protected CXF still disclosed /etc/hosts through the XOP file reference" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java8_file_sensitive_read".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    cat "${protected_dir}/cxf-xop-file-hosts.response" >&2 || true
    echo "missing java8_file_sensitive_read block event for CXF CVE-2024-28752" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Apache CXF CVE-2024-28752 Java8 acceptance passed"
