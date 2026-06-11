#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

compose=(docker compose -f docker-compose.java21.yml)
if [[ -n "${OHMYRASP_JAVA21_TOMCAT_VERSIONS:-}" ]]; then
  read -r -a versions <<< "$OHMYRASP_JAVA21_TOMCAT_VERSIONS"
else
  versions=(11 10 9)
fi
services=()

for version in "${versions[@]}"; do
  services+=("tomcat${version}-java21-baseline" "tomcat${version}-java21-protected")
done

baseline_port() {
  case "$1" in
    11) echo "${OHMYRASP_TOMCAT11_JAVA21_BASELINE_PORT:-18230}" ;;
    10) echo "${OHMYRASP_TOMCAT10_JAVA21_BASELINE_PORT:-18232}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA21_BASELINE_PORT:-18234}" ;;
    *) echo "unsupported Java 21 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

protected_port() {
  case "$1" in
    11) echo "${OHMYRASP_TOMCAT11_JAVA21_PROTECTED_PORT:-18231}" ;;
    10) echo "${OHMYRASP_TOMCAT10_JAVA21_PROTECTED_PORT:-18233}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA21_PROTECTED_PORT:-18235}" ;;
    *) echo "unsupported Java 21 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

for version in "${versions[@]}"; do
  rm -rf "logs/tomcat${version}-java21-baseline" "logs/tomcat${version}-java21-protected"
  mkdir -p "logs/tomcat${version}-java21-baseline" "logs/tomcat${version}-java21-protected"
done

"${compose[@]}" build --pull "${services[@]}"
"${compose[@]}" up -d "${services[@]}"

cleanup() {
  for version in "${versions[@]}"; do
    "${compose[@]}" logs --no-color "tomcat${version}-java21-baseline" \
      > "logs/tomcat${version}-java21-baseline/tomcat.log" || true
    "${compose[@]}" logs --no-color "tomcat${version}-java21-protected" \
      > "logs/tomcat${version}-java21-protected/tomcat.log" || true
  done
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for() {
  local name="$1"
  local url="$2"
  for _ in $(seq 1 120); do
    if curl -fsS "${url}/rasp/health" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "${name} did not become healthy at ${url}" >&2
  exit 1
}

typed_payload_body() {
  printf "%s" "argumentCollection=<wddxPacket version='1.0'><header/><data><struct type='xcom.sun.rowset.JdbcRowSetImplx'><var name='dataSourceName'><string>ldap://127.0.0.1:1389/Exploit</string></var><var name='autoCommit'><boolean value='true'/></var></struct></data></wddxPacket>"
}

run_baseline() {
  local version="$1"
  local url="$2"
  local dir="logs/tomcat${version}-java21-baseline"
  local upload_file="${dir}/java-archive-upload.jar"
  local paths=(
    normal
    command
    command-shell
    jndi
    deserialization
    file-read
    file-write
    ssrf-metadata
    ssrf-loopback
    archive-traversal
    classloader
    rmi-classloader
    jdbc-h2
    jdbc-derby
    jdbc-mysql
    script
    compile
    jaas
    jmx-remote-config
    jmx-file-write
    xml-decoder-runtime
    xml-decoder-webshell
    xxe-file
  )
  for path in "${paths[@]}"; do
    curl -fsS "${url}/rasp/java17/${path}" > "${dir}/${path//-/_}.response"
  done
  curl -fsS -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "$(typed_payload_body)" \
    "${url}/rasp/java17/typed-payload" > "${dir}/typed_payload.response"
  if ! grep -q "java17 typed payload attempted" "${dir}/typed_payload.response"; then
    cat "${dir}/typed_payload.response" >&2
    echo "baseline tomcat${version}-java21 typed payload did not reach endpoint" >&2
    exit 1
  fi
  printf 'PK\003\004ohmyrasp-java21-upload' > "$upload_file"
  curl -fsS \
    -F "file=@${upload_file};filename=Evil.jar;type=application/java-archive" \
    "${url}/rasp/java17/plugin/add" > "${dir}/upload_java_archive.response"
  if ! grep -q "java17 upload attempted 1" "${dir}/upload_java_archive.response"; then
    cat "${dir}/upload_java_archive.response" >&2
    echo "baseline tomcat${version}-java21 upload did not reach multipart endpoint" >&2
    exit 1
  fi
}

verify_startup_and_normal() {
  local version="$1"
  local url="$2"
  local log="logs/tomcat${version}-java21-protected/events.jsonl"
  curl -fsS "${url}/rasp/java17/normal" > "logs/tomcat${version}-java21-protected/normal.response"

  for marker in \
      '"event":"ohmyrasp-java17-agent-start"' \
      '"java_version":"21.' \
      '"instrumentation":"available"' \
      '"request_hook":"installed"' \
      '"file_hook":"installed"' \
      '"upload_hook":"installed"' \
      '"archive_hook":"installed"' \
      '"url_hook":"installed"' \
      '"classloader_hook":"installed"' \
      '"jdbc_hook":"installed"' \
      '"script_hook":"installed"' \
      '"java_compile_hook":"installed"' \
      '"jaas_hook":"installed"' \
      '"jmx_hook":"installed"' \
      '"java_beans_hook":"installed"' \
      '"xxe_hook":"installed"'; do
    if ! grep -q "$marker" "$log"; then
      cat "$log" >&2
      echo "missing Java 21 runtime startup marker ${marker} on Tomcat ${version}" >&2
      exit 1
    fi
  done
  if grep -q '"event":"ohmyrasp-detection"' "$log"; then
    cat "$log" >&2
    echo "Java 21 normal traffic produced a detection on Tomcat ${version}" >&2
    exit 1
  fi
}

expect_block() {
  local version="$1"
  local name="$2"
  local algorithm="$3"
  local path="$4"
  local url="http://localhost:$(protected_port "$version")"
  local log="logs/tomcat${version}-java21-protected/events.jsonl"
  local status
  status="$(curl -sS -o "logs/tomcat${version}-java21-protected/${name}.response" \
    -w "%{http_code}" "${url}${path}" || true)"
  if [[ "$status" =~ ^2 ]]; then
    echo "protected tomcat${version}-java21 ${name} unexpectedly returned ${status}" >&2
    cat "logs/tomcat${version}-java21-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected tomcat${version}-java21 ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked tomcat${version}-java21 ${name}"
}

expect_block_form() {
  local version="$1"
  local name="$2"
  local algorithm="$3"
  local path="$4"
  local url="http://localhost:$(protected_port "$version")"
  local log="logs/tomcat${version}-java21-protected/events.jsonl"
  local status
  status="$(curl -sS -o "logs/tomcat${version}-java21-protected/${name}.response" \
    -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "$(typed_payload_body)" \
    "${url}${path}" || true)"
  if [[ "$status" =~ ^2 ]]; then
    echo "protected tomcat${version}-java21 ${name} unexpectedly returned ${status}" >&2
    cat "logs/tomcat${version}-java21-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected tomcat${version}-java21 ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked tomcat${version}-java21 ${name}"
}

expect_block_upload() {
  local version="$1"
  local name="$2"
  local algorithm="$3"
  local url="http://localhost:$(protected_port "$version")"
  local log="logs/tomcat${version}-java21-protected/events.jsonl"
  local upload_file="logs/tomcat${version}-java21-protected/java-archive-upload.jar"
  local status
  printf 'PK\003\004ohmyrasp-java21-upload' > "$upload_file"
  status="$(curl -sS -o "logs/tomcat${version}-java21-protected/${name}.response" \
    -w "%{http_code}" \
    -F "file=@${upload_file};filename=Evil.jar;type=application/java-archive" \
    "${url}/rasp/java17/plugin/add" || true)"
  if [[ "$status" =~ ^2 ]] \
      && grep -q "java17 upload attempted 1" "logs/tomcat${version}-java21-protected/${name}.response"; then
    echo "protected tomcat${version}-java21 ${name} unexpectedly returned ${status}" >&2
    cat "logs/tomcat${version}-java21-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected tomcat${version}-java21 ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked tomcat${version}-java21 ${name}"
}

for version in "${versions[@]}"; do
  baseline_url="http://localhost:$(baseline_port "$version")"
  protected_url="http://localhost:$(protected_port "$version")"
  wait_for "tomcat${version}-java21-baseline" "$baseline_url"
  wait_for "tomcat${version}-java21-protected" "$protected_url"
  run_baseline "$version" "$baseline_url"
  verify_startup_and_normal "$version" "$protected_url"
  expect_block "$version" command java17_command_execution_exploit_primitive /rasp/java17/command
  expect_block "$version" command_shell java17_command_execution_shell_meta /rasp/java17/command-shell
  expect_block "$version" jndi java17_jndi_remote_lookup /rasp/java17/jndi
  expect_block_form "$version" typed_payload java17_request_typed_payload_deserialization /rasp/java17/typed-payload
  expect_block "$version" deserialization java17_deserialization_gadget_class /rasp/java17/deserialization
  expect_block "$version" file_read java17_file_sensitive_read /rasp/java17/file-read
  expect_block "$version" file_write java17_file_script_write /rasp/java17/file-write
  expect_block "$version" ssrf_metadata java17_ssrf_cloud_metadata /rasp/java17/ssrf-metadata
  expect_block "$version" ssrf_loopback java17_ssrf_loopback_admin /rasp/java17/ssrf-loopback
  expect_block "$version" archive_traversal java17_archive_entry_traversal_write /rasp/java17/archive-traversal
  expect_block "$version" classloader java17_classloader_remote_codebase /rasp/java17/classloader
  expect_block "$version" rmi_classloader java17_classloader_remote_codebase /rasp/java17/rmi-classloader
  expect_block "$version" jdbc_h2 java17_jdbc_h2_code_execution /rasp/java17/jdbc-h2
  expect_block "$version" jdbc_derby java17_jdbc_derby_code_loading /rasp/java17/jdbc-derby
  expect_block "$version" jdbc_mysql java17_jdbc_mysql_deserialization /rasp/java17/jdbc-mysql
  expect_block "$version" script java17_script_engine_runtime_execution /rasp/java17/script
  expect_block "$version" compile java17_java_compile_runtime_execution /rasp/java17/compile
  expect_block "$version" jaas java17_jaas_jndi_remote_provider /rasp/java17/jaas
  expect_block "$version" jmx_remote_config java17_jmx_remote_config_source /rasp/java17/jmx-remote-config
  expect_block "$version" jmx_file_write java17_jmx_script_file_write /rasp/java17/jmx-file-write
  expect_block "$version" xml_decoder_runtime java17_xml_decoder_runtime_execution /rasp/java17/xml-decoder-runtime
  expect_block "$version" xml_decoder_webshell java17_xml_decoder_script_file_write /rasp/java17/xml-decoder-webshell
  expect_block "$version" xxe_file java17_xxe_external_entity_protocol /rasp/java17/xxe-file
  expect_block_upload "$version" upload_java_archive fileUpload_java_archive
done

echo "java21 acceptance passed with Java17-compatible agent on Tomcat versions: ${versions[*]} baseline/protected containers"
