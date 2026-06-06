#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_HUGEGRAPH_43441_IMAGE:-vulhub/hugegraph:1.3.0}"
baseline_name="${OHMYRASP_VULHUB_HUGEGRAPH_43441_BASELINE_NAME:-ohmyrasp-vulhub-hugegraph43441-baseline}"
protected_name="${OHMYRASP_VULHUB_HUGEGRAPH_43441_PROTECTED_NAME:-ohmyrasp-vulhub-hugegraph43441-protected}"
baseline_port="${OHMYRASP_VULHUB_HUGEGRAPH_43441_BASELINE_PORT:-18432}"
protected_port="${OHMYRASP_VULHUB_HUGEGRAPH_43441_PROTECTED_PORT:-18433}"
host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"
baseline_dir="logs/vulhub-hugegraph-1.3.0-43441-java11-baseline"
protected_dir="logs/vulhub-hugegraph-1.3.0-43441-java11-protected"
protected_log="${protected_dir}/events.jsonl"
default_jwt="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJhZG1pbiIsInVzZXJfaWQiOiItMzA6YWRtaW4iLCJleHAiOjk3Mzk1MjM0ODN9.mnafQi6x9nlMz1OcPQu4xAyiq91Ig5tUFhGsktNXKqg"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

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

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 20 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

wait_for_hugegraph_auth() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl_status "${dir}/ready-${attempt}.response" "http://127.0.0.1:${port}/graphs")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "401" ]] \
      && grep -Fq "Authentication credentials are required" "${dir}/ready-${attempt}.response"; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "HugeGraph container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "HugeGraph did not expose authenticated /graphs at ${port}" >&2
  exit 1
}

get_graphs() {
  local port="$1"
  local output="$2"
  shift 2
  curl_status "$output" "$@" "http://127.0.0.1:${port}/graphs"
}

wait_for_protected_startup() {
  for attempt in $(seq 1 180); do
    if grep -Fq '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java 11 startup event in HugeGraph protected container" >&2
  exit 1
}

default_jwt_block_count() {
  grep -Ec '"algorithm":"java11_request_default_jwt_secret".*"action":"block"' "$protected_log" \
    || true
}

wait_for_default_jwt_block() {
  local previous="$1"
  local count
  for attempt in $(seq 1 30); do
    count="$(default_jwt_block_count)"
    if (( count > previous )); then
      printf 'default_jwt_block_attempt=%s count=%s\n' "$attempt" "$count" \
        >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing java11_request_default_jwt_secret block event for HugeGraph CVE-2024-43441" >&2
  exit 1
}

run_baseline() {
  docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
    -e PASSWORD=vulhub \
    "$image" >/dev/null

  wait_for_hugegraph_auth "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(get_graphs "$baseline_port" "${baseline_dir}/graphs-unauth.response")"
  printf 'baseline_unauth_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "401" ]] \
    || ! grep -Fq "Authentication credentials are required" "${baseline_dir}/graphs-unauth.response"; then
    cat "${baseline_dir}/graphs-unauth.response" >&2 || true
    echo "baseline HugeGraph did not reject unauthenticated /graphs" >&2
    exit 1
  fi

  status="$(get_graphs "$baseline_port" "${baseline_dir}/graphs-default-jwt.response" \
    -H "Authorization: Bearer ${default_jwt}")"
  printf 'baseline_default_jwt_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] \
    || ! grep -Fq '"graphs":["hugegraph"]' "${baseline_dir}/graphs-default-jwt.response"; then
    cat "${baseline_dir}/graphs-default-jwt.response" >&2 || true
    echo "baseline HugeGraph did not accept the README default JWT" >&2
    exit 1
  fi

  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  docker run -d --name "$protected_name" -p "${protected_port}:8080" \
    -e PASSWORD=vulhub \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true" \
    "$image" >/dev/null

  wait_for_protected_startup
  wait_for_hugegraph_auth "$protected_name" "$protected_port" "$protected_dir"
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "HugeGraph protected startup produced a detection before default-JWT traffic" >&2
    exit 1
  fi

  local status
  status="$(get_graphs "$protected_port" "${protected_dir}/graphs-unauth.response")"
  printf 'protected_unauth_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if [[ "$status" != "401" ]] \
    || ! grep -Fq "Authentication credentials are required" "${protected_dir}/graphs-unauth.response"; then
    cat "${protected_dir}/graphs-unauth.response" >&2 || true
    echo "protected HugeGraph did not preserve unauthenticated /graphs behavior" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "HugeGraph protected unauthenticated request produced a detection" >&2
    exit 1
  fi

  local previous_count
  previous_count="$(default_jwt_block_count)"
  status="$(get_graphs "$protected_port" "${protected_dir}/graphs-default-jwt.response" \
    -H "Authorization: Bearer ${default_jwt}")"
  printf 'protected_default_jwt_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  wait_for_default_jwt_block "$previous_count"
  if [[ "$status" == "200" ]] \
    && grep -Fq '"graphs":["hugegraph"]' "${protected_dir}/graphs-default-jwt.response"; then
    cat "${protected_dir}/graphs-default-jwt.response" >&2 || true
    echo "protected HugeGraph still returned graph metadata with the default JWT" >&2
    exit 1
  fi
  if grep -Fq "$default_jwt" "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected HugeGraph log leaked the default JWT" >&2
    exit 1
  fi
}

run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f "$protected_name" >/dev/null 2>&1 || true

echo "vulhub HugeGraph 1.3.0 CVE-2024-43441 Java11 acceptance passed"
