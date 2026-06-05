#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

vulhub_dir="${OHMYRASP_VULHUB_TOMCAT_12615_DIR:-/home/ubuntu/vulhub/tomcat/CVE-2017-12615}"
image="${OHMYRASP_VULHUB_TOMCAT_12615_IMAGE:-ohmyrasp/vulhub-tomcat:8.5.19-cve-2017-12615}"
baseline_name="${OHMYRASP_VULHUB_TOMCAT_12615_BASELINE_NAME:-ohmyrasp-vulhub-tomcat-12615-baseline}"
protected_name="${OHMYRASP_VULHUB_TOMCAT_12615_PROTECTED_NAME:-ohmyrasp-vulhub-tomcat-12615-protected}"
baseline_port="${OHMYRASP_VULHUB_TOMCAT_12615_BASELINE_PORT:-19112}"
protected_port="${OHMYRASP_VULHUB_TOMCAT_12615_PROTECTED_PORT:-19113}"
shell_path="${OHMYRASP_VULHUB_TOMCAT_12615_SHELL_PATH:-/ohmyrasp12615.jsp}"
shell_put_path="${OHMYRASP_VULHUB_TOMCAT_12615_PUT_PATH:-${shell_path}/}"
shell_marker="${OHMYRASP_VULHUB_TOMCAT_12615_MARKER:-ohmyrasp12615:}"
baseline_dir="logs/vulhub-tomcat-2017-12615-java8-baseline"
protected_dir="logs/vulhub-tomcat-2017-12615-java8-protected"
protected_log="${protected_dir}/events.jsonl"

build_vulhub_image() {
  docker build -t "$image" "$vulhub_dir"
}

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_tomcat() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl -sS -o "${dir}/ready-${attempt}.html" -w "%{http_code}" \
        "http://127.0.0.1:${port}/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Tomcat did not expose the web root at ${port}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java8 agent startup event for Tomcat protected container" >&2
  exit 1
}

write_payload() {
  local dir="$1"
  printf '<%% out.print("%s" + System.getProperty("java.version")); %%>' "$shell_marker" \
    > "${dir}/shell.jsp"
}

put_shell() {
  local port="$1"
  local dir="$2"
  curl -sS -o "${dir}/put.response" -w "%{http_code}" \
    -X PUT --data-binary "@${dir}/shell.jsp" \
    "http://127.0.0.1:${port}${shell_put_path}" || true
}

get_shell() {
  local port="$1"
  local dir="$2"
  curl -sS -o "${dir}/get.response" -w "%{http_code}" \
    "http://127.0.0.1:${port}${shell_path}" || true
}

run_baseline() {
  local put_status
  local get_status
  write_payload "$baseline_dir"
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8080" \
    "$image" >/dev/null

  wait_for_tomcat "$baseline_name" "$baseline_port" "$baseline_dir"
  put_status="$(put_shell "$baseline_port" "$baseline_dir")"
  printf 'put_status=%s\n' "$put_status" >> "${baseline_dir}/attempts.log"
  get_status="$(get_shell "$baseline_port" "$baseline_dir")"
  printf 'get_status=%s\n' "$get_status" >> "${baseline_dir}/attempts.log"
  if grep -Fq "$shell_marker" "${baseline_dir}/get.response"; then
    copy_artifacts "$baseline_name" "$baseline_dir"
    docker rm -f "$baseline_name" >/dev/null 2>&1 || true
    return
  fi
  cat "${baseline_dir}/put.response" >&2 || true
  cat "${baseline_dir}/get.response" >&2 || true
  docker logs "$baseline_name" >&2 || true
  echo "baseline Tomcat did not execute the uploaded JSP" >&2
  exit 1
}

run_protected() {
  local put_status
  local get_status
  write_payload "$protected_dir"
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8080" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "CATALINA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_tomcat "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Tomcat protected container produced a detection before exploit traffic" >&2
    exit 1
  fi

  put_status="$(put_shell "$protected_port" "$protected_dir")"
  printf 'put_status=%s\n' "$put_status" >> "${protected_dir}/attempts.log"
  get_status="$(get_shell "$protected_port" "$protected_dir")"
  printf 'get_status=%s\n' "$get_status" >> "${protected_dir}/attempts.log"
  if grep -Fq "$shell_marker" "${protected_dir}/get.response"; then
    cat "$protected_log" >&2 || true
    echo "protected Tomcat executed the uploaded JSP" >&2
    exit 1
  fi
  for attempt in $(seq 1 30); do
    printf 'protected_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if grep -Eq '"algorithm":"java8_file_script_write".*"action":"block"' "$protected_log"; then
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/put.response" >&2 || true
  cat "${protected_dir}/get.response" >&2 || true
  echo "missing java8_file_script_write block event for Tomcat CVE-2017-12615" >&2
  exit 1
}

build_vulhub_image
rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
chmod 777 "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Tomcat CVE-2017-12615 Java8 acceptance passed"
