#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_WEBLOGIC_2894_IMAGE:-vulhub/weblogic:12.2.1.3-2018}"
baseline_name="${OHMYRASP_VULHUB_WEBLOGIC_2894_BASELINE_NAME:-ohmyrasp-weblogic2894-baseline}"
protected_name="${OHMYRASP_VULHUB_WEBLOGIC_2894_PROTECTED_NAME:-ohmyrasp-weblogic2894-protected}"
baseline_port="${OHMYRASP_VULHUB_WEBLOGIC_2894_BASELINE_PORT:-19620}"
protected_port="${OHMYRASP_VULHUB_WEBLOGIC_2894_PROTECTED_PORT:-19621}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-weblogic-12.2.1.3-2894-java8-baseline"
protected_dir="logs/vulhub-weblogic-12.2.1.3-2894-java8-protected"
payload_dir="logs/vulhub-weblogic-12.2.1.3-2894-java8-payload"
protected_log="${protected_dir}/events.jsonl"
payload_name="ohmyrasp-wl2894.jsp"
payload_marker="OHMYRASP_WL2894_BASELINE_MARKER"
payload_file="${payload_dir}/${payload_name}"
web_root="/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css"
keystore_dir="${web_root}/config/keystore"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker exec "$name" sh -lc \
      "find '${keystore_dir}' -maxdepth 1 -type f -name '*${payload_name}' -print 2>/dev/null || true" \
      > "${dir}/keystore-files.txt" 2>&1 || true
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
    echo "WebLogic CVE-2018-2894 image did not report a Java 8 runtime" >&2
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
  local console wsutc startup
  for attempt in $(seq 1 240); do
    console="$(curl_status "${dir}/ready-console-${attempt}.html" "http://127.0.0.1:${port}/console")"
    wsutc="$(curl_status "${dir}/ready-wsutc-${attempt}.html" "http://127.0.0.1:${port}/ws_utc/config.do")"
    startup="yes"
    if [[ "$require_startup" == "true" ]]; then
      startup="no"
      grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log" && startup="yes"
    fi
    printf 'ready_attempt=%s console=%s wsutc=%s startup=%s\n' \
      "$attempt" "$console" "$wsutc" "$startup" >> "${dir}/attempts.log"
    if [[ "$console" == "200" || "$console" == "302" || "$console" == "401" || "$console" == "404" ]] \
        && [[ "$wsutc" == "200" ]] \
        && [[ "$startup" == "yes" ]]; then
      cp "${dir}/ready-wsutc-${attempt}.html" "${dir}/wsutc-ready.html"
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

configure_work_dir() {
  local port="$1"
  local output="$2"
  local status attempt attempt_output
  for attempt in $(seq 1 45); do
    attempt_output="${output}.${attempt}"
    status="$(curl_status "$attempt_output" \
      -X POST "http://127.0.0.1:${port}/ws_utc/resources/setting/options" \
      -d setting_id=general \
      --data-urlencode "BasicConfigOptions.workDir=${web_root}" \
      -d BasicConfigOptions.proxyHost= \
      -d BasicConfigOptions.proxyPort=80)"
    printf 'configure_workdir_attempt=%s status=%s\n' "$attempt" "$status" \
      >> "$(dirname "$output")/attempts.log"
    if [[ "$status" == "200" ]] && grep -Fq '<state>ok</state>' "$attempt_output"; then
      cp "$attempt_output" "$output"
      return
    fi
    sleep 2
  done
  cat "$attempt_output" >&2 || true
  echo "failed to configure WebLogic WS_UTC Work Home Dir on ${port}" >&2
  exit 1
}

upload_jsp() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -X POST "http://127.0.0.1:${port}/ws_utc/resources/setting/keystore" \
    -F ks_name=ohmyrasp2894 \
    -F ks_edit_mode=false \
    -F ks_password_front= \
    -F ks_password= \
    -F ks_password_changed=false \
    -F "ks_filename=@${payload_file};filename=${payload_name};type=application/octet-stream"
}

block_count() {
  grep -Ec '"hook":"MultipartUpload.filename".*"algorithm":"fileUpload_multipart_script".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

assert_startup_quiet() {
  if ! grep -Fq '"request_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 request hook startup marker in protected WebLogic container" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected WebLogic produced a detection before CVE-2018-2894 traffic" >&2
    exit 1
  fi
}

run_baseline() {
  start_baseline
  wait_for_weblogic "$baseline_name" "$baseline_port" "$baseline_dir"
  configure_work_dir "$baseline_port" "${baseline_dir}/configure-workdir.response"

  local status upload_id access_path
  status="$(upload_jsp "$baseline_port" "${baseline_dir}/upload.response")"
  printf 'baseline_upload_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq "<keyStore>${payload_name}</keyStore>" "${baseline_dir}/upload.response"; then
    cat "${baseline_dir}/upload.response" >&2 || true
    echo "baseline WebLogic CVE-2018-2894 JSP upload did not succeed" >&2
    exit 1
  fi
  upload_id="$(sed -n 's/.*<id>\([^<][^<]*\)<\/id>.*/\1/p' "${baseline_dir}/upload.response" | head -n 1)"
  if [[ -z "$upload_id" ]]; then
    cat "${baseline_dir}/upload.response" >&2 || true
    echo "baseline WebLogic CVE-2018-2894 upload response did not include an id" >&2
    exit 1
  fi
  access_path="/ws_utc/css/config/keystore/${upload_id}_${payload_name}"
  status="$(curl_status "${baseline_dir}/uploaded-jsp.response" "http://127.0.0.1:${baseline_port}${access_path}")"
  printf 'baseline_jsp_status=%s path=%s\n' "$status" "$access_path" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq "$payload_marker" "${baseline_dir}/uploaded-jsp.response"; then
    cat "${baseline_dir}/uploaded-jsp.response" >&2 || true
    echo "baseline WebLogic CVE-2018-2894 uploaded JSP did not execute" >&2
    exit 1
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  start_protected
  wait_for_weblogic "$protected_name" "$protected_port" "$protected_dir" true
  assert_startup_quiet
  configure_work_dir "$protected_port" "${protected_dir}/configure-workdir.response"

  local previous_count status after_count
  previous_count="$(block_count)"
  status="$(upload_jsp "$protected_port" "${protected_dir}/upload.response")"
  after_count="$(block_count)"
  printf 'protected_upload_status=%s previous_block_count=%s after_block_count=%s\n' \
    "$status" "$previous_count" "$after_count" >> "${protected_dir}/attempts.log"
  if (( after_count <= previous_count )); then
    cat "$protected_log" >&2 || true
    echo "missing fileUpload_multipart_script block event for WebLogic CVE-2018-2894" >&2
    exit 1
  fi
  if ! grep -Fq "\"filename\":\"${payload_name}\"" "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "WebLogic CVE-2018-2894 block event did not record the JSP filename" >&2
    exit 1
  fi
  if grep -Fq '<keyStoreItem>' "${protected_dir}/upload.response"; then
    cat "${protected_dir}/upload.response" >&2 || true
    echo "protected WebLogic CVE-2018-2894 returned a successful keystore upload response" >&2
    exit 1
  fi
  if docker exec "$protected_name" sh -lc \
      "find '${keystore_dir}' -maxdepth 1 -type f -name '*${payload_name}' 2>/dev/null | grep -q ."; then
    cat "$protected_log" >&2 || true
    echo "protected WebLogic CVE-2018-2894 still wrote ${payload_name}" >&2
    exit 1
  fi
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
printf '%s\n' "<%@ page import=\"java.util.*\" %><% out.print(\"${payload_marker}\"); %>" > "$payload_file"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

verify_image_java8
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f -v "$protected_name" >/dev/null 2>&1 || true

echo "vulhub WebLogic 12.2.1.3 CVE-2018-2894 Java8 acceptance passed"
