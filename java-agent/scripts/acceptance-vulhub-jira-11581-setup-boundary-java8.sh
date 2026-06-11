#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_JIRA_11581_IMAGE:-vulhub/jira:8.1.0}"
name="${OHMYRASP_VULHUB_JIRA_11581_NAME:-ohmyrasp-jira-11581-setup-boundary}"
port="${OHMYRASP_VULHUB_JIRA_11581_PORT:-19720}"
base_dir="logs/vulhub-jira-8.1.0-11581-setup-boundary-java8"

copy_artifacts() {
  mkdir -p "$base_dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${base_dir}/container.log" 2>&1 || true
    docker exec "$name" sh -lc \
      'tail -n 200 /opt/atlassian/jira/logs/catalina.out 2>/dev/null || true; echo "---"; find /var/atlassian/application-data/jira -maxdepth 2 -type f 2>/dev/null | sort | head -100' \
      > "${base_dir}/runtime-state.txt" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts
  docker rm -f -v "$name" >/dev/null 2>&1 || true
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

verify_image_setup_boundary() {
  docker run --rm --entrypoint sh "$image" -lc '
    home="${JIRA_HOME:-/var/atlassian/application-data/jira}"
    java -version
    printf "JIRA_HOME=%s\n" "$home"
    if [ ! -d "$home" ]; then
      printf "missing_jira_home=%s\n" "$home"
      exit 2
    fi
    first="$(find "$home" -mindepth 1 -maxdepth 1 -print -quit)"
    if [ -n "$first" ]; then
      printf "first_jira_home_entry=%s\n" "$first"
      exit 3
    fi
    printf "jira_home_empty=true\n"
  ' > "${base_dir}/image-setup-boundary.txt" 2>&1

  if ! grep -Fq '1.8.0_212' "${base_dir}/image-setup-boundary.txt"; then
    cat "${base_dir}/image-setup-boundary.txt" >&2 || true
    echo "Jira CVE-2019-11581 image did not report expected Java 8u212 runtime" >&2
    exit 1
  fi
  if ! grep -Fq 'jira_home_empty=true' "${base_dir}/image-setup-boundary.txt"; then
    cat "${base_dir}/image-setup-boundary.txt" >&2 || true
    echo "Jira CVE-2019-11581 image did not start from an empty Jira home" >&2
    exit 1
  fi
}

wait_for_startup_redirect() {
  local status location
  for attempt in $(seq 1 240); do
    status="$(curl_capture "${base_dir}/root-${attempt}.html" "http://127.0.0.1:${port}/")"
    location="$(location_header "${base_dir}/root-${attempt}.html.headers" || true)"
    printf 'root_attempt=%s status=%s location=%s\n' "$attempt" "$status" "$location" \
      >> "${base_dir}/attempts.log"
    if [[ "$status" == "302" && "$location" == *"/startup.jsp?returnTo=%2Fdefault.jsp"* ]]; then
      cp "${base_dir}/root-${attempt}.html.headers" "${base_dir}/root-startup-redirect.headers"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "Jira CVE-2019-11581 container stopped before startup redirect" >&2
      exit 1
    fi
    sleep 2
  done

  docker logs "$name" >&2 || true
  echo "Jira CVE-2019-11581 did not redirect / to startup setup on ${port}" >&2
  exit 1
}

probe_contact_form_boundary() {
  local status location payload
  payload="\$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime', null).invoke(null, null).exec('whoami').toString()"
  status="$(curl_capture "${base_dir}/contact-form.response" \
    "http://127.0.0.1:${port}/secure/ContactAdministrators!default.jspa")"
  location="$(location_header "${base_dir}/contact-form.response.headers" || true)"
  printf 'contact_form_status=%s location=%s\n' "$status" "$location" >> "${base_dir}/attempts.log"
  if [[ "$status" != "302" || "$location" != *"/startup.jsp?returnTo=%2Fsecure%2FContactAdministrators%21default.jspa"* ]]; then
    cat "${base_dir}/contact-form.response.headers" >&2 || true
    echo "Jira CVE-2019-11581 ContactAdministrators form did not redirect to startup setup" >&2
    exit 1
  fi

  status="$(curl_capture "${base_dir}/contact-post.response" \
    -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "from=test@test.com" \
    --data-urlencode "subject=${payload}" \
    --data-urlencode "details=v" \
    --data-urlencode "atl_token=dummy" \
    "http://127.0.0.1:${port}/secure/ContactAdministrators.jspa")"
  location="$(location_header "${base_dir}/contact-post.response.headers" || true)"
  printf 'contact_post_status=%s location=%s\n' "$status" "$location" >> "${base_dir}/attempts.log"
  if [[ "$status" != "302" || "$location" != *"/startup.jsp?returnTo=%2Fsecure%2FContactAdministrators.jspa"* ]]; then
    cat "${base_dir}/contact-post.response.headers" >&2 || true
    echo "Jira CVE-2019-11581 template payload POST did not redirect to startup setup" >&2
    exit 1
  fi
}

rm -rf "$base_dir"
mkdir -p "$base_dir"
docker rm -f -v "$name" >/dev/null 2>&1 || true

verify_image_setup_boundary

docker run -d --name "$name" \
  -p "${port}:8080" \
  "$image" >/dev/null

wait_for_startup_redirect
probe_contact_form_boundary
copy_artifacts
docker rm -f -v "$name" >/dev/null 2>&1 || true

echo "vulhub Jira CVE-2019-11581 Java8 setup boundary passed"
