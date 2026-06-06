#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_METERSPHERE_45788_IMAGE:-vulhub/metersphere:1.15.4}"
mysql_image="${OHMYRASP_VULHUB_METERSPHERE_45788_MYSQL_IMAGE:-mysql:5.7}"
kafka_image="${OHMYRASP_VULHUB_METERSPHERE_45788_KAFKA_IMAGE:-apache/kafka:3.7.0}"
network="${OHMYRASP_VULHUB_METERSPHERE_45788_NETWORK:-ohmyrasp-vulhub-metersphere45788}"
db_name="${OHMYRASP_VULHUB_METERSPHERE_45788_DB_NAME:-ohmyrasp-vulhub-metersphere45788-db}"
kafka_name="${OHMYRASP_VULHUB_METERSPHERE_45788_KAFKA_NAME:-ohmyrasp-vulhub-metersphere45788-kafka}"
baseline_name="${OHMYRASP_VULHUB_METERSPHERE_45788_BASELINE_NAME:-ohmyrasp-vulhub-metersphere45788-baseline}"
protected_name="${OHMYRASP_VULHUB_METERSPHERE_45788_PROTECTED_NAME:-ohmyrasp-vulhub-metersphere45788-protected}"
baseline_port="${OHMYRASP_VULHUB_METERSPHERE_45788_BASELINE_PORT:-19282}"
protected_port="${OHMYRASP_VULHUB_METERSPHERE_45788_PROTECTED_PORT:-19283}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-metersphere-1.15.4-45788-java8-baseline"
protected_dir="logs/vulhub-metersphere-1.15.4-45788-java8-protected"
payload_dir="logs/vulhub-metersphere-1.15.4-45788-java8-payload"
protected_log="${protected_dir}/events.jsonl"
case_id="ohmyrasp-case-45788"
node_id="ohmyrasp-node-45788"
malicious_order_type=",if(1=1,sleep(2),0)"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
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

curl_status_time() {
  local output="$1"
  shift
  local result
  result="$(curl --max-time 30 -sS -o "$output" -w "%{http_code} %{time_total}" "$@" \
    2>"${output}.err" || true)"
  if [[ -z "$result" ]]; then
    result="000 0"
  fi
  printf "%s" "$result"
}

wait_for_metersphere() {
  local name="$1"
  local port="$2"
  local dir="$3"
  mkdir -p "$dir"
  local result status
  for attempt in $(seq 1 120); do
    result="$(curl_status_time "${dir}/ready-${attempt}.response" "http://127.0.0.1:${port}/")"
    status="${result%% *}"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" != "000" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "MeterSphere container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "MeterSphere did not become ready at ${port}" >&2
  exit 1
}

verify_image_java8_lts() {
  mkdir -p "$payload_dir"
  docker run --rm --entrypoint java "$image" -version > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Eq 'version "1\.8\.' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "MeterSphere CVE-2021-45788 image did not report a Java 8 runtime" >&2
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

login() {
  local port="$1"
  local dir="$2"
  local cookie="${dir}/cookies.txt"
  local login_json="${dir}/signin.json"
  curl --max-time 20 -sS -c "$cookie" -b "$cookie" "http://127.0.0.1:${port}/login" >/dev/null
  curl --max-time 30 -sS -c "$cookie" -b "$cookie" \
    -H 'Content-Type: application/json' \
    --data-binary '{"username":"admin","password":"metersphere"}' \
    "http://127.0.0.1:${port}/signin" > "$login_json"
  if ! grep -Fq '"success":true' "$login_json"; then
    cat "$login_json" >&2
    echo "MeterSphere login failed at ${port}" >&2
    exit 1
  fi
}

project_id_from_login() {
  local dir="$1"
  sed -n 's/.*"lastProjectId":"\([^"]*\)".*/\1/p' "${dir}/signin.json"
}

csrf_from_login() {
  local dir="$1"
  sed -n 's/.*"csrfToken":"\([^"]*\)".*/\1/p' "${dir}/signin.json"
}

session_from_cookie() {
  local dir="$1"
  awk '/MS_SESSION_ID/ {print $7}' "${dir}/cookies.txt" | tail -n 1
}

insert_testcase() {
  local project_id="$1"
  local now
  now="$(date +%s%3N)"
  docker exec "$db_name" mysql -uroot -proot -D metersphere -e "
insert ignore into test_case_node (id, project_id, name, parent_id, level, create_time, update_time, pos, create_user)
values ('${node_id}', '${project_id}', 'ohmyrasp', null, 1, ${now}, ${now}, 1, 'admin');
insert into test_case (id, node_id, node_path, project_id, name, type, maintainer, priority, method, prerequisite, remark, steps, create_time, update_time, sort, num, review_status, tags, status, step_description, expected_result, custom_fields, step_model, custom_num, create_user, \`order\`)
values ('${case_id}', '${node_id}', '/ohmyrasp', '${project_id}', '${case_id}', 'functional', 'admin', 'P0', 'manual', '', '', '[]', ${now}, ${now}, 1, 1, 'Prepare', '', 'Prepare', '', '', '{}', 'STEP', '1', 'admin', 5000)
on duplicate key update update_time=values(update_time), status='Prepare';" >/dev/null
}

write_case_list_body() {
  local output="$1"
  local project_id="$2"
  local order_type="$3"
  cat > "$output" <<JSON
{"projectId":"${project_id}","orders":[{"name":"name","type":"${order_type}"}],"components":[],"filters":{},"planId":"","nodeIds":[],"selectAll":false,"unSelectIds":[],"selectThisWeedData":false,"selectThisWeedRelevanceData":false,"caseCoverage":null}
JSON
}

post_case_list() {
  local port="$1"
  local dir="$2"
  local body="$3"
  local output="$4"
  local csrf
  csrf="$(csrf_from_login "$dir")"
  curl_status_time "$output" \
    -b "${dir}/cookies.txt" \
    -H 'Content-Type: application/json' \
    -H "CSRF-TOKEN: ${csrf}" \
    --data-binary "@${body}" \
    "http://127.0.0.1:${port}/test/case/list/1/10"
}

assert_time_at_least() {
  local value="$1"
  local minimum="$2"
  if ! awk -v value="$value" -v minimum="$minimum" 'BEGIN { exit !(value >= minimum) }'; then
    echo "expected response time ${value} to be at least ${minimum}" >&2
    exit 1
  fi
}

assert_no_protected_detection() {
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected MeterSphere produced a detection before exploit traffic" >&2
    exit 1
  fi
}

assert_no_leaks() {
  local dir="$1"
  local csrf session
  csrf="$(csrf_from_login "$dir")"
  session="$(session_from_cookie "$dir")"
  if grep -Fq "$csrf" "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected MeterSphere log leaked CSRF token" >&2
    exit 1
  fi
  if [[ -n "$session" ]] && grep -Fq "$session" "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected MeterSphere log leaked session id" >&2
    exit 1
  fi
  if grep -Fq "$malicious_order_type" "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected MeterSphere log leaked raw SQL order value" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
docker rm -f -v "$baseline_name" "$protected_name" "$db_name" "$kafka_name" >/dev/null 2>&1 || true
docker network rm "$network" >/dev/null 2>&1 || true

verify_image_java8_lts
start_dependencies

start_metersphere "$baseline_name" "$baseline_port"
wait_for_metersphere "$baseline_name" "$baseline_port" "$baseline_dir"
login "$baseline_port" "$baseline_dir"
baseline_project_id="$(project_id_from_login "$baseline_dir")"
insert_testcase "$baseline_project_id"
write_case_list_body "${payload_dir}/normal.json" "$baseline_project_id" "asc"
write_case_list_body "${payload_dir}/sqli.json" "$baseline_project_id" "$malicious_order_type"

normal_result="$(post_case_list "$baseline_port" "$baseline_dir" "${payload_dir}/normal.json" "${baseline_dir}/normal.response")"
normal_status="${normal_result%% *}"
if [[ "$normal_status" != "200" ]] || ! grep -Fq "$case_id" "${baseline_dir}/normal.response"; then
  cat "${baseline_dir}/normal.response" >&2 || true
  echo "baseline MeterSphere normal case-list request failed" >&2
  exit 1
fi

sqli_result="$(post_case_list "$baseline_port" "$baseline_dir" "${payload_dir}/sqli.json" "${baseline_dir}/sqli.response")"
sqli_status="${sqli_result%% *}"
sqli_time="${sqli_result#* }"
if [[ "$sqli_status" != "200" ]] || ! grep -Fq "$case_id" "${baseline_dir}/sqli.response"; then
  cat "${baseline_dir}/sqli.response" >&2 || true
  echo "baseline MeterSphere SQLi request did not complete successfully" >&2
  exit 1
fi
assert_time_at_least "$sqli_time" "1.5"

start_metersphere "$protected_name" "$protected_port" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true"
wait_for_metersphere "$protected_name" "$protected_port" "$protected_dir"
if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in protected MeterSphere container" >&2
  exit 1
fi
if ! grep -q '"sql_identifier_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 SQL identifier hook startup marker" >&2
  exit 1
fi
assert_no_protected_detection

login "$protected_port" "$protected_dir"
protected_project_id="$(project_id_from_login "$protected_dir")"
write_case_list_body "${payload_dir}/protected-normal.json" "$protected_project_id" "asc"
write_case_list_body "${payload_dir}/protected-sqli.json" "$protected_project_id" "$malicious_order_type"
normal_result="$(post_case_list "$protected_port" "$protected_dir" "${payload_dir}/protected-normal.json" "${protected_dir}/normal.response")"
normal_status="${normal_result%% *}"
if [[ "$normal_status" != "200" ]] || ! grep -Fq "$case_id" "${protected_dir}/normal.response"; then
  cat "${protected_dir}/normal.response" >&2 || true
  echo "protected MeterSphere normal case-list request failed" >&2
  exit 1
fi
assert_no_protected_detection

sqli_result="$(post_case_list "$protected_port" "$protected_dir" "${payload_dir}/protected-sqli.json" "${protected_dir}/sqli.response")"
sqli_status="${sqli_result%% *}"
sqli_time="${sqli_result#* }"
if [[ "$sqli_status" != "500" ]]; then
  cat "${protected_dir}/sqli.response" >&2 || true
  echo "protected MeterSphere SQLi request was not blocked" >&2
  exit 1
fi
if ! grep -q '"hook":"MyBatis.BoundSql".*"algorithm":"java8_sql_identifier_injection".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing java8_sql_identifier_injection block event for MeterSphere CVE-2021-45788" >&2
  exit 1
fi
if grep -Fq "$case_id" "${protected_dir}/sqli.response"; then
  cat "${protected_dir}/sqli.response" >&2 || true
  echo "protected MeterSphere SQLi response still returned case-list data" >&2
  exit 1
fi
if ! awk -v value="$sqli_time" 'BEGIN { exit !(value < 1.0) }'; then
  echo "protected MeterSphere SQLi response took ${sqli_time}s; expected pre-query block" >&2
  exit 1
fi
assert_no_leaks "$protected_dir"

echo "Vulhub MeterSphere CVE-2021-45788 Java 8 acceptance passed"
