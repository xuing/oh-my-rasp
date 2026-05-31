#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

BASELINE_URL="http://localhost:${OHMYRASP_BASELINE_PORT:-18080}"
PROTECTED_URL="http://localhost:${OHMYRASP_PROTECTED_PORT:-18081}"
PROTECTED_LOG="logs/protected/events.jsonl"

rm -rf logs/baseline logs/protected
mkdir -p logs/baseline logs/protected

docker compose build --pull
docker compose up -d

cleanup() {
  docker compose logs --no-color baseline > logs/baseline/tomcat.log || true
  docker compose logs --no-color protected > logs/protected/tomcat.log || true
}
trap cleanup EXIT

wait_for() {
  local name="$1"
  local url="$2"
  for _ in $(seq 1 90); do
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

missing_redirect=0

expect_block() {
  local name="$1"
  shift
  local outfile="logs/protected/$(slug "$name").response"
  local final
  final="$(final_url "$outfile" "$@")"
  if [[ "$final" == *"/rasp/blocked"* ]]; then
    echo "blocked ${name}"
  else
    echo "missing protected redirect for ${name}; final URL was ${final}" >&2
    missing_redirect=1
  fi
}

expect_not_blocked() {
  local name="$1"
  shift
  local outfile="logs/baseline/$(slug "$name").response"
  local final
  final="$(final_url "$outfile" "$@")"
  if [[ "$final" == *"/rasp/blocked"* ]]; then
    echo "baseline unexpectedly redirected for ${name}; final URL was ${final}" >&2
    missing_redirect=1
  else
    echo "baseline ${name}"
  fi
}

wait_for baseline "$BASELINE_URL"
wait_for protected "$PROTECTED_URL"

curl -fsS "${BASELINE_URL}/" | grep -q "OhMyRasp"
curl -fsS "${PROTECTED_URL}/" | grep -q "OhMyRasp"
curl -fsS "${BASELINE_URL}/rasp/ui" | grep -q "OhMyRasp Comparative Testbed"
curl -fsS "${PROTECTED_URL}/rasp/ui" | grep -q "OhMyRasp Comparative Testbed"
curl -fsS "${PROTECTED_URL}/rasp/cases" | grep -q "Command user input"
curl -fsS "${PROTECTED_URL}/rasp/blocked?algorithm=test&hook=test&message=test" | grep -q "Request intercepted"

expect_not_blocked baseline_command -G --data-urlencode "cmd=sh" --data-urlencode "arg=-c" --data-urlencode "arg=cat /etc/passwd; id" "${BASELINE_URL}/rasp/command"
expect_not_blocked baseline_file_read -G --data-urlencode "path=/etc/passwd" "${BASELINE_URL}/rasp/file/read"
expect_not_blocked baseline_upload_policy "${BASELINE_URL}/rasp/policy/upload-script"

expect_block request_scanner -A "sqlmap/1.7" "${PROTECTED_URL}/rasp/request"
expect_block request_unusual -H "User-Agent:" "${PROTECTED_URL}/rasp/request"
expect_block xss_userinput -G -A "Mozilla/5.0" --data-urlencode "q=<script>alert(1)</script>" "${PROTECTED_URL}/rasp/request"
expect_block command_userinput -G --data-urlencode "cmd=sh" --data-urlencode "arg=-c" --data-urlencode "arg=cat /etc/passwd; id" "${PROTECTED_URL}/rasp/command"
expect_block command_common "${PROTECTED_URL}/rasp/command/common"
expect_block command_error "${PROTECTED_URL}/rasp/command/error"
expect_block command_dnslog "${PROTECTED_URL}/rasp/command/dnslog"
expect_block command_reflect "${PROTECTED_URL}/rasp/command/reflect"
expect_block readFile_userinput -G --data-urlencode "path=/etc/passwd" "${PROTECTED_URL}/rasp/file/read"
expect_block readFile_unwanted "${PROTECTED_URL}/rasp/file/read-sensitive"
expect_block readFile_outsideWebroot "${PROTECTED_URL}/rasp/file/read-outside"
expect_block readFile_userinput_http -G --data-urlencode "file=http://127.0.0.1/internal" "${PROTECTED_URL}/rasp/policy/read-http"
expect_block readFile_userinput_unwanted -G --data-urlencode "file=file:///etc/passwd" "${PROTECTED_URL}/rasp/policy/read-unwanted"
expect_block writeFile_script -G --data-urlencode "path=/usr/local/tomcat/webapps/ROOT/shell.jsp" "${PROTECTED_URL}/rasp/file/write"
expect_block writeFile_reflect "${PROTECTED_URL}/rasp/file/write-reflect"
expect_block writeFile_NTFS "${PROTECTED_URL}/rasp/policy/write-ntfs"
expect_block deleteFile_userinput -G --data-urlencode "path=/tmp/ohmyrasp-delete-target.txt" "${PROTECTED_URL}/rasp/file/delete"
expect_block directory_userinput -G --data-urlencode "path=/etc" "${PROTECTED_URL}/rasp/directory"
expect_block directory_unwanted "${PROTECTED_URL}/rasp/directory/root"
expect_block directory_reflect "${PROTECTED_URL}/rasp/policy/directory-reflect"
expect_block ssrf_aws -G --max-time 3 --data-urlencode "url=http://169.254.169.254/latest/meta-data/" "${PROTECTED_URL}/rasp/ssrf"
expect_block ssrf_userinput -G --data-urlencode "url=http://127.0.0.1/admin" "${PROTECTED_URL}/rasp/policy/ssrf-userinput"
expect_block ssrf_common "${PROTECTED_URL}/rasp/policy/ssrf-common"
expect_block ssrf_protocol "${PROTECTED_URL}/rasp/policy/ssrf-protocol"
expect_block ssrf_obfuscate "${PROTECTED_URL}/rasp/policy/ssrf-obfuscate"
expect_block dns_blacklist -G --max-time 3 --data-urlencode "host=probe.dnslog.cn" "${PROTECTED_URL}/rasp/dns"
expect_block jndi_disable_all -G --max-time 3 --data-urlencode "name=ldap://127.0.0.1:1389/a" "${PROTECTED_URL}/rasp/jndi"
expect_block sql_userinput -G --data-urlencode "value=' OR '1'='1" "${PROTECTED_URL}/rasp/sql"
expect_block sql_policy "${PROTECTED_URL}/rasp/policy/sql-policy"
expect_block sql_exception "${PROTECTED_URL}/rasp/policy/sql-exception"
expect_block sql_regex "${PROTECTED_URL}/rasp/policy/sql-regex"
expect_block deserialization_blacklist "${PROTECTED_URL}/rasp/deserialize"
expect_block xxe_protocol "${PROTECTED_URL}/rasp/policy/xxe-protocol"
expect_block xxe_file "${PROTECTED_URL}/rasp/policy/xxe-file"
expect_block include_userinput -G --data-urlencode "file=/etc/passwd" "${PROTECTED_URL}/rasp/policy/include-userinput"
expect_block include_protocol "${PROTECTED_URL}/rasp/policy/include-protocol"
expect_block fileUpload_multipart_script "${PROTECTED_URL}/rasp/policy/upload-script"
expect_block fileUpload_multipart_html "${PROTECTED_URL}/rasp/policy/upload-html"
expect_block fileUpload_multipart_exe "${PROTECTED_URL}/rasp/policy/upload-exe"
expect_block fileUpload_webdav "${PROTECTED_URL}/rasp/policy/webdav"
expect_block rename_webshell "${PROTECTED_URL}/rasp/policy/rename"
expect_block link_webshell "${PROTECTED_URL}/rasp/policy/link"
expect_block ognl_blacklist "${PROTECTED_URL}/rasp/policy/ognl"
expect_block ognl_length_limit "${PROTECTED_URL}/rasp/policy/ognl-length"
expect_block eval_regex "${PROTECTED_URL}/rasp/policy/eval"
expect_block loadLibrary_unc "${PROTECTED_URL}/rasp/policy/loadlib"
expect_block response_dataLeak "${PROTECTED_URL}/rasp/policy/response"
expect_block xss_echo "${PROTECTED_URL}/rasp/policy/xss-echo"
expect_block webshell_eval -G --data-urlencode "code=system('id')" "${PROTECTED_URL}/rasp/policy/webshell-eval"
expect_block webshell_command -G --data-urlencode "cmd=sh -c id" "${PROTECTED_URL}/rasp/policy/webshell-command"
expect_block webshell_file_put_contents -G --data-urlencode "file=shell.jsp" "${PROTECTED_URL}/rasp/policy/webshell-file"
expect_block webshell_callable "${PROTECTED_URL}/rasp/policy/webshell-callable"
expect_block webshell_ld_preload "${PROTECTED_URL}/rasp/policy/webshell-ld"

sleep 2
docker compose exec -T protected sh -c 'chmod 666 /opt/ohmyrasp/logs/events.jsonl' || true

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

missing=0
for algorithm in "${required_algorithms[@]}"; do
  if grep -q "\"algorithm\":\"${algorithm}\"" "$PROTECTED_LOG"; then
    echo "ok ${algorithm}"
  else
    echo "missing ${algorithm}" >&2
    missing=1
  fi
done

if [[ "$missing_redirect" -ne 0 || "$missing" -ne 0 ]]; then
  echo "acceptance failed; see ${PROTECTED_LOG}, logs/baseline/tomcat.log, and logs/protected/tomcat.log" >&2
  exit 1
fi

echo "acceptance passed; protected events collected in ${PROTECTED_LOG}"
