#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

cleanup_names=()
cleanup_dirs=()

cleanup() {
  local name
  for name in "${cleanup_names[@]}"; do
    local dir=""
    case "$name" in
      *100-baseline) dir="logs/vulhub-shiro-1.0.0-java8-baseline" ;;
      *100-protected) dir="logs/vulhub-shiro-1.0.0-java8-protected" ;;
      *151-baseline) dir="logs/vulhub-shiro-1.5.1-java8-baseline" ;;
      *151-protected) dir="logs/vulhub-shiro-1.5.1-java8-protected" ;;
    esac
    if [[ "$dir" != "" ]]; then
      docker logs "$name" > "${dir}/container.log" 2>&1 || true
    fi
  done
  if ((${#cleanup_names[@]} > 0)); then
    docker rm -f "${cleanup_names[@]}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 120); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Shiro demo at ${port}" >&2
  exit 1
}

http_status() {
  local url="$1"
  local output="$2"
  curl -sS --path-as-is -i -o "$output" -w "%{http_code}" "$url" || true
}

expect_redirect_to_login() {
  local status="$1"
  local output="$2"
  local label="$3"
  if [[ "$status" != "302" ]] || ! grep -qi 'Location: .*login' "$output"; then
    cat "$output" >&2 || true
    echo "${label} did not redirect direct admin access to login" >&2
    exit 1
  fi
}

expect_startup_without_detection() {
  local log="$1"
  local startup_event="$2"
  local label="$3"
  if ! grep -q "\"event\":\"${startup_event}\"" "$log"; then
    cat "$log" >&2 || true
    echo "missing Java 8 startup event in ${label}" >&2
    exit 1
  fi
  if ! grep -q '"request_hook":"installed"' "$log"; then
    cat "$log" >&2
    echo "missing Java 8 request hook startup marker in ${label}" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$log"; then
    cat "$log" >&2
    echo "${label} produced a detection before the exploit request" >&2
    exit 1
  fi
}

run_case() {
  local version="$1"
  local image="$2"
  local suffix="$3"
  local baseline_name="$4"
  local protected_name="$5"
  local baseline_port="$6"
  local protected_port="$7"
  local direct_path="$8"
  local exploit_path="$9"
  local success_marker="${10}"
  local protected_failure_marker="${11}"
  local baseline_dir="logs/vulhub-shiro-${version}-java8-baseline"
  local protected_dir="logs/vulhub-shiro-${version}-java8-protected"
  local protected_log="${protected_dir}/events.jsonl"

  cleanup_names+=("$baseline_name" "$protected_name")
  rm -rf "$baseline_dir" "$protected_dir"
  mkdir -p "$baseline_dir" "$protected_dir"
  : > "$protected_log"
  chmod 666 "$protected_log"

  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

  docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
    "$image" >/dev/null

  docker run -d --name "$protected_name" -p "${protected_port}:8080" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    "$image" \
    java -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar \
      -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl \
      -Dohmyrasp.java8.block=true \
      -jar /shirodemo-1.0-SNAPSHOT.jar \
    >/dev/null

  wait_for "$baseline_name" "$baseline_port"
  wait_for "$protected_name" "$protected_port"

  local baseline_direct_status
  baseline_direct_status="$(
    http_status \
      "http://127.0.0.1:${baseline_port}${direct_path}" \
      "${baseline_dir}/direct-admin.headers"
  )"
  expect_redirect_to_login "$baseline_direct_status" "${baseline_dir}/direct-admin.headers" \
    "baseline Shiro ${version}"

  local protected_direct_status
  protected_direct_status="$(
    http_status \
      "http://127.0.0.1:${protected_port}${direct_path}" \
      "${protected_dir}/direct-admin.headers"
  )"
  expect_redirect_to_login "$protected_direct_status" "${protected_dir}/direct-admin.headers" \
    "protected Shiro ${version}"
  expect_startup_without_detection "$protected_log" "ohmyrasp-java8-agent-start" \
    "Shiro ${version} protected container"

  local baseline_status
  baseline_status="$(
    http_status \
      "http://127.0.0.1:${baseline_port}${exploit_path}" \
      "${baseline_dir}/${suffix}-bypass.response"
  )"
  if [[ "$baseline_status" != "200" ]] \
      || ! grep -q "$success_marker" "${baseline_dir}/${suffix}-bypass.response"; then
    cat "${baseline_dir}/${suffix}-bypass.response" >&2 || true
    echo "baseline Shiro ${version} exploit path did not bypass authentication" >&2
    exit 1
  fi

  local protected_status
  protected_status="$(
    http_status \
      "http://127.0.0.1:${protected_port}${exploit_path}" \
      "${protected_dir}/${suffix}-bypass.response"
  )"
  if [[ "$protected_status" =~ ^2 ]] \
      || grep -q "$protected_failure_marker" "${protected_dir}/${suffix}-bypass.response"; then
    cat "${protected_dir}/${suffix}-bypass.response" >&2 || true
    echo "protected Shiro ${version} exploit path was not blocked" >&2
    exit 1
  fi
  if ! grep -q '"algorithm":"java8_request_path_confusion".*"action":"block"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "missing java8_request_path_confusion block event for Shiro ${version}" >&2
    exit 1
  fi
}

run_case \
  "1.0.0" \
  "${OHMYRASP_VULHUB_SHIRO100_IMAGE:-vulhub/shiro:1.0.0}" \
  "cve-2010-3863" \
  "${OHMYRASP_VULHUB_SHIRO100_BASELINE_NAME:-ohmyrasp-vulhub-shiro100-baseline}" \
  "${OHMYRASP_VULHUB_SHIRO100_PROTECTED_NAME:-ohmyrasp-vulhub-shiro100-protected}" \
  "${OHMYRASP_VULHUB_SHIRO100_BASELINE_PORT:-18750}" \
  "${OHMYRASP_VULHUB_SHIRO100_PROTECTED_PORT:-18751}" \
  "/admin" \
  "/./admin" \
  "You have successfully logged in" \
  "You have successfully logged in"

run_case \
  "1.5.1" \
  "${OHMYRASP_VULHUB_SHIRO151_IMAGE:-vulhub/shiro:1.5.1}" \
  "cve-2020-1957" \
  "${OHMYRASP_VULHUB_SHIRO151_BASELINE_NAME:-ohmyrasp-vulhub-shiro151-baseline}" \
  "${OHMYRASP_VULHUB_SHIRO151_PROTECTED_NAME:-ohmyrasp-vulhub-shiro151-protected}" \
  "${OHMYRASP_VULHUB_SHIRO151_BASELINE_PORT:-18752}" \
  "${OHMYRASP_VULHUB_SHIRO151_PROTECTED_PORT:-18753}" \
  "/admin/" \
  "/xxx/..;/admin/" \
  "Account Info Page" \
  "Account Info Page"

echo "vulhub Shiro 1.0.0 CVE-2010-3863 and Shiro 1.5.1 CVE-2020-1957 Java8 acceptance passed"
