#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_AJ_REPORT_IMAGE:-vulhub/aj-report:1.4.0}"
mysql_image="${OHMYRASP_VULHUB_AJ_REPORT_MYSQL_IMAGE:-mysql:5.7}"
baseline_name="${OHMYRASP_VULHUB_AJ_REPORT_BASELINE_NAME:-ohmyrasp-vulhub-aj-report-baseline}"
protected_name="${OHMYRASP_VULHUB_AJ_REPORT_PROTECTED_NAME:-ohmyrasp-vulhub-aj-report-protected}"
baseline_db_name="${OHMYRASP_VULHUB_AJ_REPORT_BASELINE_DB_NAME:-ohmyrasp-vulhub-aj-report-baseline-db}"
protected_db_name="${OHMYRASP_VULHUB_AJ_REPORT_PROTECTED_DB_NAME:-ohmyrasp-vulhub-aj-report-protected-db}"
baseline_network="${OHMYRASP_VULHUB_AJ_REPORT_BASELINE_NETWORK:-ohmyrasp-aj-report-baseline-net}"
protected_network="${OHMYRASP_VULHUB_AJ_REPORT_PROTECTED_NETWORK:-ohmyrasp-aj-report-protected-net}"
baseline_port="${OHMYRASP_VULHUB_AJ_REPORT_BASELINE_PORT:-19095}"
protected_port="${OHMYRASP_VULHUB_AJ_REPORT_PROTECTED_PORT:-19096}"
baseline_dir="logs/vulhub-aj-report-cnvd-2024-15077-java8-baseline"
protected_dir="logs/vulhub-aj-report-cnvd-2024-15077-java8-protected"
protected_log="${protected_dir}/events.jsonl"
exploit_path="/dataSetParam/verification;swagger-ui/"
payload='{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"id\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss=\"\";while((line = r.readLine()) != null){ss+=line};return ss;}"}'

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker logs "$baseline_db_name" > "${baseline_dir}/mysql.log" 2>&1 || true
  docker logs "$protected_db_name" > "${protected_dir}/mysql.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" "$baseline_db_name" "$protected_db_name" >/dev/null 2>&1 || true
  docker network rm "$baseline_network" "$protected_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_mysql() {
  local name="$1"
  local dir="$2"
  for _ in $(seq 1 180); do
    if docker exec "$name" mysqladmin ping -uroot -proot --silent >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  docker logs "$name" > "${dir}/mysql.log" 2>&1 || true
  echo "${name} did not expose MySQL" >&2
  exit 1
}

wait_for_aj_report() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for _ in $(seq 1 240); do
    status="$(curl --max-time 2 -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" =~ ^[23] ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" > "${dir}/container.log" 2>&1 || true
  echo "${name} did not expose AJ-Report at ${port}" >&2
  exit 1
}

send_validation_payload() {
  local port="$1"
  local output="$2"
  curl --max-time 20 -sS -i -o "$output" -w "%{http_code}" \
    -X POST -H 'Content-Type: application/json;charset=UTF-8' \
    --data-binary "$payload" \
    "http://127.0.0.1:${port}${exploit_path}" || true
}

expect_protected_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 startup event in protected AJ-Report container" >&2
    exit 1
  fi
  if ! grep -q '"script_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 script hook startup marker in protected AJ-Report container" >&2
    exit 1
  fi
  if ! grep -q '"xxe_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing Java 8 XXE hook startup marker in protected AJ-Report container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected AJ-Report startup produced a detection before exploit traffic" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
chmod 755 "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" "$baseline_db_name" "$protected_db_name" >/dev/null 2>&1 || true
docker network rm "$baseline_network" "$protected_network" >/dev/null 2>&1 || true
docker network create "$baseline_network" >/dev/null
docker network create "$protected_network" >/dev/null

docker run -d --name "$baseline_db_name" --network "$baseline_network" --network-alias db \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=aj_report \
  "$mysql_image" >/dev/null
docker run -d --name "$protected_db_name" --network "$protected_network" --network-alias db \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=aj_report \
  "$mysql_image" >/dev/null

wait_for_mysql "$baseline_db_name" "$baseline_dir"
wait_for_mysql "$protected_db_name" "$protected_dir"

docker run -d --name "$baseline_name" --network "$baseline_network" \
  -p "${baseline_port}:9095" \
  -e MYSQL_HOST=db -e MYSQL_PORT=3306 -e MYSQL_DB=aj_report \
  -e MYSQL_USERNAME=root -e MYSQL_PASSWORD=root \
  "$image" >/dev/null

docker run -d --name "$protected_name" --network "$protected_network" \
  -p "${protected_port}:9095" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  -e MYSQL_HOST=db -e MYSQL_PORT=3306 -e MYSQL_DB=aj_report \
  -e MYSQL_USERNAME=root -e MYSQL_PASSWORD=root \
  "$image" >/dev/null

wait_for_aj_report "$baseline_name" "$baseline_port" "$baseline_dir"
wait_for_aj_report "$protected_name" "$protected_port" "$protected_dir"
expect_protected_startup_without_detection

baseline_status="$(send_validation_payload "$baseline_port" "${baseline_dir}/verification.response")"
if [[ "$baseline_status" != "200" ]]; then
  cat "${baseline_dir}/verification.response" >&2 || true
  echo "baseline AJ-Report validation request returned unexpected status ${baseline_status}" >&2
  exit 1
fi
if ! grep -q 'uid=0(root)' "${baseline_dir}/verification.response"; then
  cat "${baseline_dir}/verification.response" >&2 || true
  echo "baseline AJ-Report validation request did not execute id" >&2
  exit 1
fi

protected_status="$(send_validation_payload "$protected_port" "${protected_dir}/verification.response")"
if [[ "$protected_status" != "200" ]]; then
  cat "${protected_dir}/verification.response" >&2 || true
  echo "protected AJ-Report validation request returned unexpected status ${protected_status}" >&2
  exit 1
fi
if grep -q 'uid=0(root)' "${protected_dir}/verification.response"; then
  cat "${protected_dir}/verification.response" >&2 || true
  echo "protected AJ-Report returned command output despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"hook":"ScriptEngine.eval".*"algorithm":"java8_script_engine_runtime_execution".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_script_engine_runtime_execution block event for AJ-Report CNVD-2024-15077" >&2
  exit 1
fi

echo "vulhub AJ-Report CNVD-2024-15077 Java8 acceptance passed"
