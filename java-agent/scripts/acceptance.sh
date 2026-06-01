#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

versions=(9 10 11)
declare -A baseline_ports=(
  [9]="${OHMYRASP_TOMCAT9_BASELINE_PORT:-18080}"
  [10]="${OHMYRASP_TOMCAT10_BASELINE_PORT:-18082}"
  [11]="${OHMYRASP_TOMCAT11_BASELINE_PORT:-18084}"
)
declare -A protected_ports=(
  [9]="${OHMYRASP_TOMCAT9_PROTECTED_PORT:-18081}"
  [10]="${OHMYRASP_TOMCAT10_PROTECTED_PORT:-18083}"
  [11]="${OHMYRASP_TOMCAT11_PROTECTED_PORT:-18085}"
)

rm -rf logs/tomcat*-baseline logs/tomcat*-protected
for version in "${versions[@]}"; do
  mkdir -p "logs/tomcat${version}-baseline" "logs/tomcat${version}-protected"
done

docker compose build --pull
docker compose up -d

cleanup() {
  for version in "${versions[@]}"; do
    docker compose logs --no-color "tomcat${version}-baseline" > "logs/tomcat${version}-baseline/tomcat.log" || true
    docker compose logs --no-color "tomcat${version}-protected" > "logs/tomcat${version}-protected/tomcat.log" || true
  done
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

slug() {
  printf "%s" "$1" | tr -c "[:alnum:]_.-" "_"
}

final_url() {
  local outfile="$1"
  shift
  curl -sS -L -o "$outfile" -w "%{url_effective}" "$@" 2>"${outfile}.err" || true
}

expect_body_contains() {
  local url="$1"
  local needle="$2"
  local body
  body="$(curl -fsS "$url")"
  if [[ "$body" != *"$needle"* ]]; then
    echo "expected ${url} to contain ${needle}" >&2
    exit 1
  fi
}

missing_redirect=0

expect_block() {
  local version="$1"
  local name="$2"
  shift 2
  local outfile="logs/tomcat${version}-protected/$(slug "$name").response"
  local final
  final="$(final_url "$outfile" "$@")"
  if [[ "$final" == *"/rasp/blocked"* ]]; then
    echo "blocked tomcat${version} ${name}"
  else
    echo "missing protected redirect for tomcat${version} ${name}; final URL was ${final}" >&2
    missing_redirect=1
  fi
}

expect_not_blocked() {
  local version="$1"
  local name="$2"
  shift 2
  local outfile="logs/tomcat${version}-baseline/$(slug "$name").response"
  local final
  final="$(final_url "$outfile" "$@")"
  if [[ "$final" == *"/rasp/blocked"* ]]; then
    echo "baseline tomcat${version} unexpectedly redirected for ${name}; final URL was ${final}" >&2
    missing_redirect=1
  else
    echo "baseline tomcat${version} ${name}"
  fi
}

run_version() {
  local version="$1"
  local baseline_url="http://localhost:${baseline_ports[$version]}"
  local protected_url="http://localhost:${protected_ports[$version]}"

  wait_for "tomcat${version}-baseline" "$baseline_url"
  wait_for "tomcat${version}-protected" "$protected_url"

  expect_body_contains "${baseline_url}/" "OhMyRasp"
  expect_body_contains "${protected_url}/" "OhMyRasp"
  expect_body_contains "${baseline_url}/rasp/ui" "OhMyRasp Comparative Testbed"
  expect_body_contains "${protected_url}/rasp/ui" "OhMyRasp Comparative Testbed"
  expect_body_contains "${protected_url}/rasp/cases" "Command user input"
  expect_body_contains "${protected_url}/rasp/environments" "tomcat${version}-protected"
  expect_body_contains "${protected_url}/rasp/labs" "expression-injection"
  expect_body_contains "${protected_url}/rasp/blocked?algorithm=test&hook=test&message=test" "Request intercepted"

  expect_not_blocked "$version" baseline_command -G --data-urlencode "cmd=sh" --data-urlencode "arg=-c" --data-urlencode "arg=cat /etc/passwd; id" "${baseline_url}/rasp/command"
  expect_not_blocked "$version" baseline_file_read -G --data-urlencode "path=/etc/passwd" "${baseline_url}/rasp/file/read"
  expect_not_blocked "$version" baseline_upload_policy "${baseline_url}/rasp/policy/upload-script"

  expect_block "$version" request_scanner -A "sqlmap/1.7" "${protected_url}/rasp/request"
  expect_block "$version" request_unusual -H "User-Agent:" "${protected_url}/rasp/request"
  expect_block "$version" xss_userinput -G -A "Mozilla/5.0" --data-urlencode "q=<script>alert(1)</script>" "${protected_url}/rasp/request"
  expect_block "$version" command_userinput -G --data-urlencode "cmd=sh" --data-urlencode "arg=-c" --data-urlencode "arg=cat /etc/passwd; id" "${protected_url}/rasp/command"
  expect_block "$version" command_common "${protected_url}/rasp/command/common"
  expect_block "$version" command_error "${protected_url}/rasp/command/error"
  expect_block "$version" command_dnslog "${protected_url}/rasp/command/dnslog"
  expect_block "$version" command_reflect "${protected_url}/rasp/command/reflect"
  expect_block "$version" readFile_userinput -G --data-urlencode "path=/etc/passwd" "${protected_url}/rasp/file/read"
  expect_block "$version" readFile_unwanted "${protected_url}/rasp/file/read-sensitive"
  expect_block "$version" readFile_outsideWebroot "${protected_url}/rasp/file/read-outside"
  expect_block "$version" readFile_userinput_http -G --data-urlencode "file=http://127.0.0.1/internal" "${protected_url}/rasp/policy/read-http"
  expect_block "$version" readFile_userinput_unwanted -G --data-urlencode "file=file:///etc/passwd" "${protected_url}/rasp/policy/read-unwanted"
  expect_block "$version" writeFile_script -G --data-urlencode "path=/usr/local/tomcat/webapps/ROOT/shell.jsp" "${protected_url}/rasp/file/write"
  expect_block "$version" writeFile_reflect "${protected_url}/rasp/file/write-reflect"
  expect_block "$version" writeFile_NTFS "${protected_url}/rasp/policy/write-ntfs"
  expect_block "$version" deleteFile_userinput -G --data-urlencode "path=/tmp/ohmyrasp-delete-target.txt" "${protected_url}/rasp/file/delete"
  expect_block "$version" directory_userinput -G --data-urlencode "path=/etc" "${protected_url}/rasp/directory"
  expect_block "$version" directory_unwanted "${protected_url}/rasp/directory/root"
  expect_block "$version" directory_reflect "${protected_url}/rasp/policy/directory-reflect"
  expect_block "$version" ssrf_aws -G --max-time 3 --data-urlencode "url=http://169.254.169.254/latest/meta-data/" "${protected_url}/rasp/ssrf"
  expect_block "$version" ssrf_userinput -G --data-urlencode "url=http://127.0.0.1/admin" "${protected_url}/rasp/policy/ssrf-userinput"
  expect_block "$version" ssrf_common "${protected_url}/rasp/policy/ssrf-common"
  expect_block "$version" ssrf_protocol "${protected_url}/rasp/policy/ssrf-protocol"
  expect_block "$version" ssrf_obfuscate "${protected_url}/rasp/policy/ssrf-obfuscate"
  expect_block "$version" dns_blacklist -G --max-time 3 --data-urlencode "host=probe.dnslog.cn" "${protected_url}/rasp/dns"
  expect_block "$version" jndi_disable_all -G --max-time 3 --data-urlencode "name=ldap://127.0.0.1:1389/a" "${protected_url}/rasp/jndi"
  expect_block "$version" sql_userinput -G --data-urlencode "value=' OR '1'='1" "${protected_url}/rasp/sql"
  expect_block "$version" sql_policy "${protected_url}/rasp/policy/sql-policy"
  expect_block "$version" sql_exception "${protected_url}/rasp/policy/sql-exception"
  expect_block "$version" sql_regex "${protected_url}/rasp/policy/sql-regex"
  expect_block "$version" deserialization_blacklist "${protected_url}/rasp/deserialize"
  expect_block "$version" xxe_protocol "${protected_url}/rasp/policy/xxe-protocol"
  expect_block "$version" xxe_file "${protected_url}/rasp/policy/xxe-file"
  expect_block "$version" include_userinput -G --data-urlencode "file=/etc/passwd" "${protected_url}/rasp/policy/include-userinput"
  expect_block "$version" include_protocol "${protected_url}/rasp/policy/include-protocol"
  expect_block "$version" fileUpload_multipart_script "${protected_url}/rasp/policy/upload-script"
  expect_block "$version" fileUpload_multipart_html "${protected_url}/rasp/policy/upload-html"
  expect_block "$version" fileUpload_multipart_exe "${protected_url}/rasp/policy/upload-exe"
  expect_block "$version" fileUpload_webdav "${protected_url}/rasp/policy/webdav"
  expect_block "$version" rename_webshell "${protected_url}/rasp/policy/rename"
  expect_block "$version" link_webshell "${protected_url}/rasp/policy/link"
  expect_block "$version" ognl_blacklist "${protected_url}/rasp/policy/ognl"
  expect_block "$version" ognl_length_limit "${protected_url}/rasp/policy/ognl-length"
  expect_block "$version" eval_regex "${protected_url}/rasp/policy/eval"
  expect_block "$version" loadLibrary_unc "${protected_url}/rasp/policy/loadlib"
  expect_block "$version" response_dataLeak "${protected_url}/rasp/policy/response"
  expect_block "$version" xss_echo "${protected_url}/rasp/policy/xss-echo"
  expect_block "$version" webshell_eval -G --data-urlencode "code=system('id')" "${protected_url}/rasp/policy/webshell-eval"
  expect_block "$version" webshell_command -G --data-urlencode "cmd=sh -c id" "${protected_url}/rasp/policy/webshell-command"
  expect_block "$version" webshell_file_put_contents -G --data-urlencode "file=shell.jsp" "${protected_url}/rasp/policy/webshell-file"
  expect_block "$version" webshell_callable "${protected_url}/rasp/policy/webshell-callable"
  expect_block "$version" webshell_ld_preload "${protected_url}/rasp/policy/webshell-ld"
}

required_algorithms=(
  request_scanner
  request_unusual
  xss_userinput
  command_reflect
  command_userinput
  command_common
  command_error
  command_dnslog
  readFile_userinput
  readFile_userinput_http
  readFile_userinput_unwanted
  readFile_unwanted
  readFile_outsideWebroot
  writeFile_NTFS
  writeFile_script
  writeFile_reflect
  deleteFile_userinput
  directory_reflect
  directory_userinput
  directory_unwanted
  ssrf_userinput
  ssrf_aws
  ssrf_common
  ssrf_obfuscate
  ssrf_protocol
  dns_blacklist
  jndi_disable_all
  sql_userinput
  sql_policy
  sql_regex
  sql_exception
  deserialization_blacklist
  xxe_protocol
  xxe_file
  include_userinput
  include_protocol
  fileUpload_multipart_script
  fileUpload_multipart_html
  fileUpload_multipart_exe
  fileUpload_webdav
  rename_webshell
  link_webshell
  ognl_blacklist
  ognl_length_limit
  eval_regex
  loadLibrary_unc
  response_dataLeak
  xss_echo
  webshell_eval
  webshell_command
  webshell_file_put_contents
  webshell_callable
  webshell_ld_preload
)

for version in "${versions[@]}"; do
  run_version "$version"
done

sleep 2
for version in "${versions[@]}"; do
  docker compose exec -T "tomcat${version}-protected" sh -c 'chmod 666 /opt/ohmyrasp/logs/events.jsonl' || true
done

missing=0
for version in "${versions[@]}"; do
  protected_log="logs/tomcat${version}-protected/events.jsonl"
  for algorithm in "${required_algorithms[@]}"; do
    if grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$protected_log"; then
      echo "ok tomcat${version} ${algorithm}"
    else
      echo "missing tomcat${version} ${algorithm} block event" >&2
      missing=1
    fi
  done
done

if [[ "$missing_redirect" -ne 0 || "$missing" -ne 0 ]]; then
  echo "acceptance failed; see logs/tomcat*-protected/events.jsonl and logs/tomcat*/tomcat.log" >&2
  exit 1
fi

echo "acceptance passed across Tomcat 9, 10, and 11"
