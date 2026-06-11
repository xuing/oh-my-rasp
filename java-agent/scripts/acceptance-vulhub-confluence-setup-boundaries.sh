#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

base_port="${OHMYRASP_VULHUB_CONFLUENCE_SETUP_BASE_PORT:-19700}"
base_dir="logs/vulhub-confluence-setup-boundaries"
current_web=""
current_db=""
current_net=""

cleanup_current() {
  if [[ -n "$current_web" ]]; then
    docker logs "$current_web" > "${current_dir}/web-container.log" 2>&1 || true
  fi
  if [[ -n "$current_db" ]]; then
    docker logs "$current_db" > "${current_dir}/db-container.log" 2>&1 || true
  fi
  docker rm -f -v "$current_web" "$current_db" >/dev/null 2>&1 || true
  if [[ -n "$current_net" ]]; then
    docker network rm "$current_net" >/dev/null 2>&1 || true
  fi
  current_web=""
  current_db=""
  current_net=""
}

cleanup() {
  cleanup_current
}
trap cleanup EXIT

curl_capture() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 60 -sS -D "${output}.headers" -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

location_header() {
  local headers="$1"
  awk 'BEGIN{IGNORECASE=1} /^location:/ {sub(/\r$/, ""); print $2; exit}' "$headers"
}

wait_for_postgres() {
  local name="$1"
  local dir="$2"
  for attempt in $(seq 1 90); do
    if docker exec "$name" pg_isready -U postgres -d confluence >/dev/null 2>&1; then
      printf 'postgres_ready_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Confluence boundary PostgreSQL container did not become ready: ${name}" >&2
  exit 1
}

wait_for_setup_redirect() {
  local port="$1"
  local dir="$2"
  local status location
  for attempt in $(seq 1 240); do
    status="$(curl_capture "${dir}/root-${attempt}.html" "http://127.0.0.1:${port}/")"
    location="$(location_header "${dir}/root-${attempt}.html.headers" || true)"
    printf 'root_attempt=%s status=%s location=%s\n' "$attempt" "$status" "$location" \
      >> "${dir}/attempts.log"
    if [[ "$status" == "302" && "$location" == *"/bootstrap/selectsetupstep.action"* ]]; then
      cp "${dir}/root-${attempt}.html.headers" "${dir}/root-redirect.headers"
      return
    fi
    if ! docker ps --filter "name=${current_web}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$current_web"; then
      docker logs "$current_web" >&2 || true
      echo "Confluence container stopped before setup redirect: ${current_web}" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$current_web" >&2 || true
  echo "Confluence did not redirect / to setup on port ${port}" >&2
  exit 1
}

record_table_count() {
  local db="$1"
  local dir="$2"
  local count
  count="$(docker exec "$db" psql -U postgres -d confluence -tAc \
    "select count(*) from information_schema.tables where table_schema='public';" \
    2>"${dir}/table-count.err" | tr -d '[:space:]')"
  printf '%s\n' "$count" > "${dir}/table-count.txt"
  if [[ "$count" != "0" ]]; then
    cat "${dir}/table-count.txt" >&2
    echo "Confluence setup boundary expected zero public tables before setup" >&2
    exit 1
  fi
}

verify_image_java() {
  local image="$1"
  local expected="$2"
  local dir="$3"
  docker run --rm --entrypoint sh "$image" -lc 'java -version' \
    > "${dir}/image-java-version.txt" 2>&1
  if ! grep -Fq "$expected" "${dir}/image-java-version.txt"; then
    cat "${dir}/image-java-version.txt" >&2 || true
    echo "Confluence image ${image} did not report expected Java marker ${expected}" >&2
    exit 1
  fi
}

assert_no_cmd_header() {
  local headers="$1"
  if grep -iq '^X-Cmd-Response:' "$headers"; then
    cat "$headers" >&2 || true
    echo "Confluence setup boundary unexpectedly returned X-Cmd-Response" >&2
    exit 1
  fi
}

probe_3396() {
  local port="$1"
  local dir="$2"
  local body='{"contentId":"786458","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc6","width":"1000","height":"1000","_template":". /web.xml"}}}'
  local status
  status="$(curl_capture "${dir}/macro-preview.response" \
    -X POST -H "Content-Type: application/json; charset=utf-8" \
    --data-binary "$body" \
    "http://127.0.0.1:${port}/rest/tinymce/1/macro/preview")"
  printf 'probe_3396_status=%s\n' "$status" >> "${dir}/attempts.log"
  if [[ "$status" != "503" ]] || ! grep -Fq 'Setup in progress' "${dir}/macro-preview.response"; then
    cat "${dir}/macro-preview.response" >&2 || true
    echo "Confluence CVE-2019-3396 uninitialized boundary did not return 503 Setup in progress" >&2
    exit 1
  fi
}

probe_26084() {
  local port="$1"
  local dir="$2"
  local status location
  status="$(curl_capture "${dir}/doenterpagevariables.response" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "queryString=\\u0027+{233*233}+\\u0027" \
    "http://127.0.0.1:${port}/pages/doenterpagevariables.action")"
  location="$(location_header "${dir}/doenterpagevariables.response.headers" || true)"
  printf 'probe_26084_status=%s location=%s\n' "$status" "$location" >> "${dir}/attempts.log"
  if [[ "$status" != "302" || "$location" != *"/bootstrap/selectsetupstep.action"* ]]; then
    cat "${dir}/doenterpagevariables.response.headers" >&2 || true
    echo "Confluence CVE-2021-26084 uninitialized boundary did not redirect to setup" >&2
    exit 1
  fi
}

probe_26134() {
  local port="$1"
  local dir="$2"
  local path='/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/'
  local status location
  status="$(curl_capture "${dir}/path-ognl.response" --path-as-is "http://127.0.0.1:${port}${path}")"
  location="$(location_header "${dir}/path-ognl.response.headers" || true)"
  printf 'probe_26134_status=%s location=%s\n' "$status" "$location" >> "${dir}/attempts.log"
  assert_no_cmd_header "${dir}/path-ognl.response.headers"
  if [[ "$status" != "302" || "$location" != *"/bootstrap/selectsetupstep.action"* ]]; then
    cat "${dir}/path-ognl.response.headers" >&2 || true
    echo "Confluence CVE-2022-26134 uninitialized boundary did not redirect to setup" >&2
    exit 1
  fi
}

probe_22515() {
  local port="$1"
  local dir="$2"
  local status location
  status="$(curl_capture "${dir}/server-info-reset.response" \
    "http://127.0.0.1:${port}/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false")"
  location="$(location_header "${dir}/server-info-reset.response.headers" || true)"
  printf 'probe_22515_reset_status=%s location=%s\n' "$status" "$location" >> "${dir}/attempts.log"
  if [[ "$status" != "302" || "$location" != *"/bootstrap/selectsetupstep.action"* ]]; then
    cat "${dir}/server-info-reset.response.headers" >&2 || true
    echo "Confluence CVE-2023-22515 setup reset did not redirect to setup in uninitialized state" >&2
    exit 1
  fi

  status="$(curl_capture "${dir}/setupadministrator.response" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "X-Atlassian-Token: no-check" \
    --data "username=vulhub&fullName=vulhub&email=admin%40vulhub.org&password=vulhub&confirm=vulhub&setup-next-button=Next" \
    "http://127.0.0.1:${port}/setup/setupadministrator.action")"
  printf 'probe_22515_admin_status=%s\n' "$status" >> "${dir}/attempts.log"
  if [[ "$status" != "500" ]]; then
    cat "${dir}/setupadministrator.response.headers" >&2 || true
    echo "Confluence CVE-2023-22515 setup administrator POST did not hit expected uninitialized 500 boundary" >&2
    exit 1
  fi
}

probe_22527() {
  local port="$1"
  local dir="$2"
  local status location
  status="$(curl_capture "${dir}/text-inline.response" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data-binary "label=\\u0027%2b#request\\u005b\\u0027.KEY_velocity.struts2.context\\u0027\\u005d.internalGet(\\u0027ognl\\u0027).findValue(#parameters.x,{})%2b\\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({\"id\"}))" \
    "http://127.0.0.1:${port}/template/aui/text-inline.vm")"
  location="$(location_header "${dir}/text-inline.response.headers" || true)"
  printf 'probe_22527_status=%s location=%s\n' "$status" "$location" >> "${dir}/attempts.log"
  assert_no_cmd_header "${dir}/text-inline.response.headers"
  if [[ "$status" != "302" || "$location" != *"/bootstrap/selectsetupstep.action"* ]]; then
    cat "${dir}/text-inline.response.headers" >&2 || true
    echo "Confluence CVE-2023-22527 text-inline payload did not redirect to setup" >&2
    exit 1
  fi
}

run_case() {
  local id="$1"
  local image="$2"
  local db_image="$3"
  local java_marker="$4"
  local probe="$5"
  local port="$6"
  current_dir="${base_dir}/${id}"
  current_web="ohmyrasp-confluence-${id}-web"
  current_db="ohmyrasp-confluence-${id}-db"
  current_net="ohmyrasp-confluence-${id}-net"

  rm -rf "$current_dir"
  mkdir -p "$current_dir"
  docker rm -f -v "$current_web" "$current_db" >/dev/null 2>&1 || true
  docker network rm "$current_net" >/dev/null 2>&1 || true

  verify_image_java "$image" "$java_marker" "$current_dir"

  docker network create "$current_net" >/dev/null
  docker run -d --name "$current_db" --network "$current_net" --network-alias db \
    -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=confluence \
    "$db_image" >/dev/null
  wait_for_postgres "$current_db" "$current_dir"
  docker run -d --name "$current_web" --network "$current_net" \
    -p "${port}:8090" "$image" >/dev/null
  wait_for_setup_redirect "$port" "$current_dir"
  record_table_count "$current_db" "$current_dir"
  "$probe" "$port" "$current_dir"
  cleanup_current
}

rm -rf "$base_dir"
mkdir -p "$base_dir"

run_case "3396" "vulhub/confluence:6.10.2" "postgres:10.7-alpine" '1.8.0_171' probe_3396 "$((base_port + 0))"
run_case "26084" "vulhub/confluence:7.4.10" "postgres:12.8-alpine" '11.0.11' probe_26084 "$((base_port + 1))"
run_case "26134" "vulhub/confluence:7.13.6" "postgres:12.8-alpine" '11.' probe_26134 "$((base_port + 2))"
run_case "22515" "vulhub/confluence:8.5.1" "postgres:15.4-alpine" '11.0.20.1' probe_22515 "$((base_port + 3))"
run_case "22527" "vulhub/confluence:8.5.3" "postgres:15.4-alpine" '11.0.21' probe_22527 "$((base_port + 4))"

echo "vulhub Confluence setup/license boundary probes passed"
