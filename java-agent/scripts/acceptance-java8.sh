#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

compose=(docker compose -f docker-compose.java8.yml)
if [[ -n "${OHMYRASP_JAVA8_TOMCAT_VERSIONS:-}" ]]; then
  read -r -a versions <<< "$OHMYRASP_JAVA8_TOMCAT_VERSIONS"
else
  versions=(10 9 8)
fi

service_prefix() {
  case "$1" in
    10) echo "tomcat10-java8" ;;
    9) echo "tomcat9-java8" ;;
    8) echo "tomcat8" ;;
    *) echo "unsupported Java 8 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

baseline_port() {
  case "$1" in
    10) echo "${OHMYRASP_TOMCAT10_JAVA8_BASELINE_PORT:-18118}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA8_BASELINE_PORT:-18120}" ;;
    8) echo "${OHMYRASP_TOMCAT8_BASELINE_PORT:-18086}" ;;
    *) echo "unsupported Java 8 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

protected_port() {
  case "$1" in
    10) echo "${OHMYRASP_TOMCAT10_JAVA8_PROTECTED_PORT:-18119}" ;;
    9) echo "${OHMYRASP_TOMCAT9_JAVA8_PROTECTED_PORT:-18121}" ;;
    8) echo "${OHMYRASP_TOMCAT8_PROTECTED_PORT:-18087}" ;;
    *) echo "unsupported Java 8 Tomcat version: $1" >&2; exit 1 ;;
  esac
}

services=()

for version in "${versions[@]}"; do
  prefix="$(service_prefix "$version")"
  services+=("${prefix}-baseline" "${prefix}-protected")
done

for version in "${versions[@]}"; do
  prefix="$(service_prefix "$version")"
  rm -rf "logs/${prefix}-baseline" "logs/${prefix}-protected"
  mkdir -p "logs/${prefix}-baseline" "logs/${prefix}-protected"
done

"${compose[@]}" build --pull "${services[@]}"
"${compose[@]}" up -d "${services[@]}"

cleanup() {
  for version in "${versions[@]}"; do
    prefix="$(service_prefix "$version")"
    "${compose[@]}" logs --no-color "${prefix}-baseline" > "logs/${prefix}-baseline/tomcat.log" || true
    "${compose[@]}" logs --no-color "${prefix}-protected" > "logs/${prefix}-protected/tomcat.log" || true
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

expect_ok() {
  local prefix="$1"
  local name="$2"
  local url="$3"
  curl -fsS "$url" > "logs/${prefix}-baseline/${name}.response"
  echo "baseline ${prefix} ${name}"
}

expect_protected_normal() {
  local prefix="$1"
  local url="$2"
  local log="logs/${prefix}-protected/events.jsonl"
  curl -fsS "${url}/rasp/java8/normal" > "logs/${prefix}-protected/normal.response"
  if grep -q '"event":"ohmyrasp-detection"' "$log"; then
    cat "$log" >&2
    echo "protected ${prefix} normal traffic produced a detection" >&2
    exit 1
  fi
  echo "protected ${prefix} normal"
}

expect_startup_hook() {
  local prefix="$1"
  local log="logs/${prefix}-protected/events.jsonl"
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$log"; then
    cat "$log" >&2 || true
    echo "missing Java 8 startup event for protected ${prefix}" >&2
    exit 1
  fi
  if ! grep -q '"request_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 8 request hook startup marker for protected ${prefix}" >&2
    exit 1
  fi
  if ! grep -q '"upload_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 8 upload hook startup marker for protected ${prefix}" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$log"; then
    cat "$log" >&2
    echo "protected ${prefix} startup or health traffic produced a detection" >&2
    exit 1
  fi
}

expect_block() {
  local prefix="$1"
  local url="$2"
  local name="$3"
  local algorithm="$4"
  local path="$5"
  local log="logs/${prefix}-protected/events.jsonl"
  local status
  status="$(curl -sS -o "logs/${prefix}-protected/${name}.response" -w "%{http_code}" "${url}${path}" || true)"
  if [[ "$status" =~ ^2 ]]; then
    echo "protected ${prefix} ${name} unexpectedly returned ${status}" >&2
    cat "logs/${prefix}-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected ${prefix} ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked ${prefix} ${name}"
}

expect_upload_ok() {
  local prefix="$1"
  local name="$2"
  local url="$3"
  local upload_file="logs/${prefix}-baseline/java-archive-upload.jar"
  printf 'PK\003\004ohmyrasp-java8-upload' > "$upload_file"
  curl -fsS \
    -F "file=@${upload_file};filename=Evil.jar;type=application/java-archive" \
    "$url" > "logs/${prefix}-baseline/${name}.response"
  if ! grep -q "upload attempted 1" "logs/${prefix}-baseline/${name}.response"; then
    cat "logs/${prefix}-baseline/${name}.response" >&2
    echo "baseline ${prefix} ${name} did not reach multipart endpoint" >&2
    exit 1
  fi
  echo "baseline ${prefix} ${name}"
}

expect_block_upload() {
  local prefix="$1"
  local url="$2"
  local name="$3"
  local algorithm="$4"
  local log="logs/${prefix}-protected/events.jsonl"
  local upload_file="logs/${prefix}-protected/java-archive-upload.jar"
  local status
  printf 'PK\003\004ohmyrasp-java8-upload' > "$upload_file"
  status="$(curl -sS -o "logs/${prefix}-protected/${name}.response" \
    -w "%{http_code}" \
    -F "file=@${upload_file};filename=Evil.jar;type=application/java-archive" \
    "${url}/rasp/java8/plugin/add" || true)"
  if [[ "$status" =~ ^2 ]] \
      && grep -q "upload attempted 1" "logs/${prefix}-protected/${name}.response"; then
    echo "protected ${prefix} ${name} unexpectedly returned ${status}" >&2
    cat "logs/${prefix}-protected/${name}.response" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$log"; then
    cat "$log" >&2
    echo "missing protected ${prefix} ${name} block event for ${algorithm}" >&2
    exit 1
  fi
  echo "blocked ${prefix} ${name}"
}

run_matrix_entry() {
  local version="$1"
  local prefix
  local baseline_url
  local protected_url
  prefix="$(service_prefix "$version")"
  baseline_url="http://localhost:$(baseline_port "$version")"
  protected_url="http://localhost:$(protected_port "$version")"

  wait_for "${prefix}-baseline" "$baseline_url"
  wait_for "${prefix}-protected" "$protected_url"
  expect_startup_hook "$prefix"

  "${compose[@]}" exec -T "${prefix}-protected" \
    sh -c ': > /opt/ohmyrasp/logs/events.jsonl && chmod 666 /opt/ohmyrasp/logs/events.jsonl'

  expect_ok "$prefix" normal "${baseline_url}/rasp/java8/normal"
  for item in \
    command:/rasp/java8/command \
    command_shell:/rasp/java8/command-shell \
    deserialization:/rasp/java8/deserialization \
    file_read:/rasp/java8/file-read \
    file_write:/rasp/java8/file-write \
    ssrf_metadata:/rasp/java8/ssrf-metadata \
    ssrf_loopback:/rasp/java8/ssrf-loopback \
    archive_traversal:/rasp/java8/archive-traversal \
    jdbc_h2:/rasp/java8/jdbc-h2 \
    jdbc_derby:/rasp/java8/jdbc-derby \
    jdbc_mysql:/rasp/java8/jdbc-mysql \
    classloader:/rasp/java8/classloader \
    rmi_classloader:/rasp/java8/rmi-classloader \
    script:/rasp/java8/script \
    compile:/rasp/java8/compile \
    jaas:/rasp/java8/jaas \
    jmx_remote_config:/rasp/java8/jmx-remote-config \
    jmx_file_write:/rasp/java8/jmx-file-write \
    xml_decoder_runtime:/rasp/java8/xml-decoder-runtime \
    xml_decoder_webshell:/rasp/java8/xml-decoder-webshell \
    jndi:/rasp/java8/jndi \
    xxe_file:/rasp/java8/xxe-file; do
    name=${item%%:*}
    path=${item#*:}
    expect_ok "$prefix" "$name" "${baseline_url}${path}"
  done
  expect_upload_ok "$prefix" upload_java_archive "${baseline_url}/rasp/java8/plugin/add"

  expect_protected_normal "$prefix" "$protected_url"
  expect_block "$prefix" "$protected_url" command java8_command_execution_exploit_primitive /rasp/java8/command
  expect_block "$prefix" "$protected_url" command_shell java8_command_execution_shell_meta /rasp/java8/command-shell
  expect_block "$prefix" "$protected_url" deserialization java8_deserialization_gadget_class /rasp/java8/deserialization
  expect_block "$prefix" "$protected_url" file_read java8_file_sensitive_read /rasp/java8/file-read
  expect_block "$prefix" "$protected_url" file_write java8_file_script_write /rasp/java8/file-write
  expect_block "$prefix" "$protected_url" ssrf_metadata java8_ssrf_cloud_metadata /rasp/java8/ssrf-metadata
  expect_block "$prefix" "$protected_url" ssrf_loopback java8_ssrf_loopback_admin /rasp/java8/ssrf-loopback
  expect_block "$prefix" "$protected_url" archive_traversal java8_archive_entry_traversal_write /rasp/java8/archive-traversal
  expect_block "$prefix" "$protected_url" jdbc_h2 java8_jdbc_h2_code_execution /rasp/java8/jdbc-h2
  expect_block "$prefix" "$protected_url" jdbc_derby java8_jdbc_derby_code_loading /rasp/java8/jdbc-derby
  expect_block "$prefix" "$protected_url" jdbc_mysql java8_jdbc_mysql_deserialization /rasp/java8/jdbc-mysql
  expect_block "$prefix" "$protected_url" classloader java8_classloader_remote_codebase /rasp/java8/classloader
  expect_block "$prefix" "$protected_url" rmi_classloader java8_classloader_remote_codebase /rasp/java8/rmi-classloader
  expect_block "$prefix" "$protected_url" script java8_script_engine_runtime_execution /rasp/java8/script
  expect_block "$prefix" "$protected_url" compile java8_java_compile_runtime_execution /rasp/java8/compile
  expect_block "$prefix" "$protected_url" jaas java8_jaas_jndi_remote_provider /rasp/java8/jaas
  expect_block "$prefix" "$protected_url" jmx_remote_config java8_jmx_remote_config_source /rasp/java8/jmx-remote-config
  expect_block "$prefix" "$protected_url" jmx_file_write java8_jmx_script_file_write /rasp/java8/jmx-file-write
  expect_block "$prefix" "$protected_url" xml_decoder_runtime java8_xml_decoder_runtime_execution /rasp/java8/xml-decoder-runtime
  expect_block "$prefix" "$protected_url" xml_decoder_webshell java8_xml_decoder_script_file_write /rasp/java8/xml-decoder-webshell
  expect_block "$prefix" "$protected_url" jndi java8_jndi_remote_lookup /rasp/java8/jndi
  expect_block "$prefix" "$protected_url" xxe_file java8_xxe_external_entity_protocol /rasp/java8/xxe-file
  expect_block_upload "$prefix" "$protected_url" upload_java_archive fileUpload_java_archive
}

for version in "${versions[@]}"; do
  run_matrix_entry "$version"
done

echo "java8 acceptance passed on Tomcat versions: ${versions[*]} baseline/protected containers"
