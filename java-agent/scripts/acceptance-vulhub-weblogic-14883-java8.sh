#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_WEBLOGIC_14883_IMAGE:-vulhub/weblogic:12.2.1.3-2018}"
baseline_name="${OHMYRASP_VULHUB_WEBLOGIC_14883_BASELINE_NAME:-ohmyrasp-weblogic14883-baseline}"
protected_name="${OHMYRASP_VULHUB_WEBLOGIC_14883_PROTECTED_NAME:-ohmyrasp-weblogic14883-protected}"
baseline_port="${OHMYRASP_VULHUB_WEBLOGIC_14883_BASELINE_PORT:-19601}"
protected_port="${OHMYRASP_VULHUB_WEBLOGIC_14883_PROTECTED_PORT:-19602}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-weblogic-12.2.1.3-14883-java8-baseline"
protected_dir="logs/vulhub-weblogic-12.2.1.3-14883-java8-protected"
payload_dir="logs/vulhub-weblogic-12.2.1.3-14883-java8-payload"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-weblogic-14883-success"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker exec "$name" sh -lc "ls -l ${marker} 2>/dev/null || true" \
      > "${dir}/marker.txt" 2>/dev/null || true
    docker exec "$name" sh -lc \
      'tail -n 180 /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log 2>/dev/null || true' \
      > "${dir}/adminserver.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

verify_image_java8() {
  docker run --rm --entrypoint sh "$image" -lc 'java -version' \
    > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'version "1.8.' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "WebLogic CVE-2020-14883 image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:7001" \
    "$image" >/dev/null
}

start_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:7001" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e USER_MEM_ARGS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true -Djava.security.egd=file:/dev/./urandom" \
    "$image" >/dev/null
}

wait_for_weblogic() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local require_startup="${4:-false}"
  local status startup
  for attempt in $(seq 1 240); do
    status="$(curl_status "${dir}/ready-${attempt}.html" "http://127.0.0.1:${port}/console")"
    startup="yes"
    if [[ "$require_startup" == "true" ]]; then
      startup="no"
      grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log" && startup="yes"
    fi
    printf 'ready_attempt=%s status=%s startup=%s\n' "$attempt" "$status" "$startup" \
      >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" || "$status" == "404" ]] \
        && [[ "$startup" == "yes" ]]; then
      cp "${dir}/ready-${attempt}.html" "${dir}/console-ready.html"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "WebLogic container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "WebLogic did not become ready on ${port}" >&2
  exit 1
}

shellsession_handle() {
  printf 'com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec('\''touch %s'\'');")' "$marker"
}

send_shellsession() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    --path-as-is \
    -G \
    --data-urlencode "_nfpb=true" \
    --data-urlencode "_pageLabel=" \
    --data-urlencode "handle=$(shellsession_handle)" \
    "http://127.0.0.1:${port}/console/css/%252e%252e%252fconsole.portal"
}

request_path_block_count() {
  grep -Ec '"hook":"HttpServlet.service".*"algorithm":"java8_request_path_confusion".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

wait_for_request_path_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(request_path_block_count)"
    if (( count > previous )); then
      printf 'request_path_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_request_path_confusion block event for WebLogic CVE-2020-14883" >&2
  exit 1
}

assert_startup_quiet() {
  if ! grep -Fq '"request_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 request hook startup marker in protected WebLogic container" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected WebLogic produced a detection before ShellSession traffic" >&2
    exit 1
  fi
}

run_baseline() {
  start_baseline
  wait_for_weblogic "$baseline_name" "$baseline_port" "$baseline_dir"
  local status attempt
  for attempt in $(seq 1 10); do
    status="$(send_shellsession "$baseline_port" "${baseline_dir}/shellsession-${attempt}.response")"
    printf 'baseline_shellsession_attempt=%s status=%s\n' "$attempt" "$status" \
      >> "${baseline_dir}/attempts.log"
    sleep 2
    if docker exec "$baseline_name" test -f "$marker"; then
      printf 'baseline_marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
      cp "${baseline_dir}/shellsession-${attempt}.response" "${baseline_dir}/shellsession.response"
      copy_artifacts "$baseline_name" "$baseline_dir"
      docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
      return
    fi
  done
  cat "${baseline_dir}/shellsession-10.response" >&2 || true
  echo "baseline WebLogic CVE-2020-14883 did not create ${marker}" >&2
  exit 1
}

run_protected() {
  start_protected
  wait_for_weblogic "$protected_name" "$protected_port" "$protected_dir" true
  assert_startup_quiet

  docker exec "$protected_name" rm -f "$marker"
  local previous_count status attempt after_count
  previous_count="$(request_path_block_count)"
  for attempt in $(seq 1 10); do
    status="$(send_shellsession "$protected_port" "${protected_dir}/shellsession-${attempt}.response")"
    printf 'protected_shellsession_attempt=%s status=%s\n' "$attempt" "$status" \
      >> "${protected_dir}/attempts.log"
    after_count="$(request_path_block_count)"
    if (( after_count > previous_count )); then
      cp "${protected_dir}/shellsession-${attempt}.response" "${protected_dir}/shellsession.response"
      break
    fi
    sleep 2
  done
  wait_for_request_path_block "$previous_count"
  if ! grep -Fq '/console/css/%252e%252e%252fconsole.portal' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "WebLogic CVE-2020-14883 block event did not record the encoded console bypass path" >&2
    exit 1
  fi
  if docker exec "$protected_name" test -f "$marker"; then
    cat "$protected_log" >&2 || true
    echo "protected WebLogic CVE-2020-14883 still created ${marker}" >&2
    exit 1
  fi
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

verify_image_java8
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f -v "$protected_name" >/dev/null 2>&1 || true

echo "vulhub WebLogic 12.2.1.3 CVE-2020-14882/14883 Java8 acceptance passed"
