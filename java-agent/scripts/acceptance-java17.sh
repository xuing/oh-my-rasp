#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

compose=(docker compose -f docker-compose.java17.yml)
if [[ -n "${OHMYRASP_JAVA17_TOMCAT_VERSIONS:-}" ]]; then
  read -r -a versions <<< "$OHMYRASP_JAVA17_TOMCAT_VERSIONS"
else
  versions=(11 10 9)
fi
services=()

for version in "${versions[@]}"; do
  services+=("tomcat${version}-java17-baseline" "tomcat${version}-java17-protected")
done

baseline_port() {
  case "$1" in
    11) echo "${OHMYRASP_TOMCAT11_JAVA17_BASELINE_PORT:-18130}" ;;
    10) echo "${OHMYRASP_TOMCAT10_JAVA17_BASELINE_PORT:-18132}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA17_BASELINE_PORT:-18134}" ;;
    *) echo "unsupported Java 17 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

protected_port() {
  case "$1" in
    11) echo "${OHMYRASP_TOMCAT11_JAVA17_PROTECTED_PORT:-18131}" ;;
    10) echo "${OHMYRASP_TOMCAT10_JAVA17_PROTECTED_PORT:-18133}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA17_PROTECTED_PORT:-18135}" ;;
    *) echo "unsupported Java 17 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

for version in "${versions[@]}"; do
  rm -rf "logs/tomcat${version}-java17-baseline" "logs/tomcat${version}-java17-protected"
  mkdir -p "logs/tomcat${version}-java17-baseline" "logs/tomcat${version}-java17-protected"
done

"${compose[@]}" build --pull "${services[@]}"
"${compose[@]}" up -d "${services[@]}"

cleanup() {
  for version in "${versions[@]}"; do
    "${compose[@]}" logs --no-color "tomcat${version}-java17-baseline" \
      > "logs/tomcat${version}-java17-baseline/tomcat.log" || true
    "${compose[@]}" logs --no-color "tomcat${version}-java17-protected" \
      > "logs/tomcat${version}-java17-protected/tomcat.log" || true
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

run_baseline() {
  local version="$1"
  local url="$2"
  local dir="logs/tomcat${version}-java17-baseline"
  curl -fsS "${url}/rasp/java17/normal" > "${dir}/normal.response"
  curl -fsS "${url}/rasp/java17/command" > "${dir}/command.response"
  curl -fsS "${url}/rasp/java17/command-shell" > "${dir}/command_shell.response"
  curl -fsS "${url}/rasp/java17/jndi" > "${dir}/jndi.response"
  curl -fsS "${url}/rasp/java17/deserialization" > "${dir}/deserialization.response"
  curl -fsS "${url}/rasp/java17/file-read" > "${dir}/file_read.response"
  curl -fsS "${url}/rasp/java17/file-write" > "${dir}/file_write.response"
  curl -fsS "${url}/rasp/java17/ssrf-metadata" > "${dir}/ssrf_metadata.response"
  curl -fsS "${url}/rasp/java17/ssrf-loopback" > "${dir}/ssrf_loopback.response"
  curl -fsS "${url}/rasp/java17/archive-traversal" > "${dir}/archive_traversal.response"
  curl -fsS "${url}/rasp/java17/classloader" > "${dir}/classloader.response"
  curl -fsS "${url}/rasp/java17/rmi-classloader" > "${dir}/rmi_classloader.response"
  curl -fsS "${url}/rasp/java17/jdbc-h2" > "${dir}/jdbc_h2.response"
  curl -fsS "${url}/rasp/java17/jdbc-derby" > "${dir}/jdbc_derby.response"
  curl -fsS "${url}/rasp/java17/jdbc-mysql" > "${dir}/jdbc_mysql.response"
  curl -fsS "${url}/rasp/java17/script" > "${dir}/script.response"
  curl -fsS "${url}/rasp/java17/compile" > "${dir}/compile.response"
  curl -fsS "${url}/rasp/java17/jaas" > "${dir}/jaas.response"
  curl -fsS "${url}/rasp/java17/jmx-remote-config" > "${dir}/jmx_remote_config.response"
  curl -fsS "${url}/rasp/java17/jmx-file-write" > "${dir}/jmx_file_write.response"
  curl -fsS "${url}/rasp/java17/xml-decoder-runtime" > "${dir}/xml_decoder_runtime.response"
  curl -fsS "${url}/rasp/java17/xml-decoder-webshell" > "${dir}/xml_decoder_webshell.response"
  curl -fsS "${url}/rasp/java17/xxe-file" > "${dir}/xxe_file.response"
}

verify_startup_and_normal() {
  local version="$1"
  local url="$2"
  local log="logs/tomcat${version}-java17-protected/events.jsonl"
  curl -fsS "${url}/rasp/java17/normal" > "logs/tomcat${version}-java17-protected/normal.response"

  if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 startup probe event on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"instrumentation":"available"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 instrumentation availability on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"request_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 request hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"file_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 file hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"archive_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 archive hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"url_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 URL hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"classloader_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 classloader hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"jdbc_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 JDBC hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"script_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 script hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"java_compile_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 Java compilation hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"jaas_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 JAAS hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"jmx_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 JMX hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"java_beans_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 JavaBeans hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if ! grep -q '"xxe_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 17 XXE hook startup marker on Tomcat ${version}" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$log"; then
    cat "$log" >&2
    echo "Java 17 normal traffic produced a detection on Tomcat ${version}" >&2
    exit 1
  fi
}

expect_block() {
  local version="$1"
  local name="$2"
  local algorithm="$3"
  local path="$4"
  local url="http://localhost:$(protected_port "$version")"
  local log="logs/tomcat${version}-java17-protected/events.jsonl"
  local status
  status="$(curl -sS -o "logs/tomcat${version}-java17-protected/${name}.response" \
    -w "%{http_code}" "${url}${path}" || true)"
  if [[ "$status" =~ ^2 ]]; then
    echo "protected tomcat${version}-java17 ${name} unexpectedly returned ${status}" >&2
    cat "logs/tomcat${version}-java17-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected tomcat${version}-java17 ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked tomcat${version}-java17 ${name}"
}

for version in "${versions[@]}"; do
  baseline_url="http://localhost:$(baseline_port "$version")"
  protected_url="http://localhost:$(protected_port "$version")"
  wait_for "tomcat${version}-java17-baseline" "$baseline_url"
  wait_for "tomcat${version}-java17-protected" "$protected_url"
  run_baseline "$version" "$baseline_url"
  verify_startup_and_normal "$version" "$protected_url"
  expect_block "$version" command java17_command_execution_exploit_primitive /rasp/java17/command
  expect_block "$version" command_shell java17_command_execution_shell_meta /rasp/java17/command-shell
  expect_block "$version" jndi java17_jndi_remote_lookup /rasp/java17/jndi
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
done

echo "java17 acceptance passed on Tomcat versions: ${versions[*]} baseline/protected containers"
