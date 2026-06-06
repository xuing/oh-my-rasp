#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_GEOSERVER_25157_IMAGE:-vulhub/geoserver:2.22.1}"
postgres_image="${OHMYRASP_VULHUB_GEOSERVER_25157_POSTGRES_IMAGE:-postgis/postgis:14-3.3-alpine}"
startup_script="${OHMYRASP_VULHUB_GEOSERVER_25157_STARTUP:-/home/ubuntu/vulhub/geoserver/CVE-2023-25157/startup.sh}"
baseline_network="${OHMYRASP_VULHUB_GEOSERVER_25157_BASELINE_NETWORK:-ohmyrasp-geoserver-25157-baseline-net}"
protected_network="${OHMYRASP_VULHUB_GEOSERVER_25157_PROTECTED_NETWORK:-ohmyrasp-geoserver-25157-protected-net}"
baseline_name="${OHMYRASP_VULHUB_GEOSERVER_25157_BASELINE_NAME:-ohmyrasp-vulhub-geoserver-25157-baseline}"
protected_name="${OHMYRASP_VULHUB_GEOSERVER_25157_PROTECTED_NAME:-ohmyrasp-vulhub-geoserver-25157-protected}"
baseline_postgres="${OHMYRASP_VULHUB_GEOSERVER_25157_BASELINE_POSTGRES:-ohmyrasp-vulhub-geoserver-25157-baseline-postgres}"
protected_postgres="${OHMYRASP_VULHUB_GEOSERVER_25157_PROTECTED_POSTGRES:-ohmyrasp-vulhub-geoserver-25157-protected-postgres}"
baseline_port="${OHMYRASP_VULHUB_GEOSERVER_25157_BASELINE_PORT:-18630}"
protected_port="${OHMYRASP_VULHUB_GEOSERVER_25157_PROTECTED_PORT:-18631}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-geoserver-25157-java17-baseline"
protected_dir="logs/vulhub-geoserver-25157-java17-protected"
protected_log="${protected_dir}/events.jsonl"
normal_query="service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example&CQL_FILTER=strStartsWith%28name%2C%27x%27%29+%3D+true"
malicious_query="service=wfs&version=1.0.0&request=GetFeature&typeName=vulhub:example&CQL_FILTER=strStartsWith%28name%2C%27x%27%27%29+%3D+true+and+1%3D%28SELECT+CAST+%28%28SELECT+version%28%29%29+AS+integer%29%29+--+%27%29+%3D+true"

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
  docker logs "$baseline_postgres" > "${baseline_dir}/postgres.log" 2>&1 || true
  docker logs "$protected_postgres" > "${protected_dir}/postgres.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" "$baseline_postgres" "$protected_postgres" \
    >/dev/null 2>&1 || true
  docker network rm "$baseline_network" "$protected_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" "$baseline_postgres" "$protected_postgres" \
  >/dev/null 2>&1 || true
docker network rm "$baseline_network" "$protected_network" >/dev/null 2>&1 || true
docker network create "$baseline_network" >/dev/null
docker network create "$protected_network" >/dev/null

wait_for_postgres() {
  local name="$1"
  for _ in $(seq 1 120); do
    if docker exec "$name" pg_isready -U postgres -d geoserver >/dev/null 2>&1; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
        | grep -q .; then
      docker logs "$name" >&2 || true
      echo "${name} exited before PostGIS was ready" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not become ready" >&2
  exit 1
}

wait_for_feature_type() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status
  for _ in $(seq 1 240); do
    status="$(curl -sS -o "$output" -w "%{http_code}" -u admin:geoserver \
      "http://127.0.0.1:${port}/geoserver/rest/workspaces/vulhub/datastores/pg/featuretypes.json" \
      2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q '"example"' "$output"; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
        | grep -q .; then
      docker logs "$name" >&2 || true
      echo "${name} exited before GeoServer feature type initialization" >&2
      exit 1
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not initialize vulhub:example" >&2
  exit 1
}

send_wfs() {
  local port="$1"
  local query="$2"
  local output="$3"
  curl -sS -o "$output" -w "%{http_code}" \
    "http://127.0.0.1:${port}/geoserver/ows?${query}" || true
}

docker run -d --name "$baseline_postgres" --network "$baseline_network" --network-alias postgres \
  -e POSTGRES_PASSWORD=vulhub \
  -e POSTGRES_DB=geoserver \
  "$postgres_image" >/dev/null

docker run -d --name "$protected_postgres" --network "$protected_network" --network-alias postgres \
  -e POSTGRES_PASSWORD=vulhub \
  -e POSTGRES_DB=geoserver \
  "$postgres_image" >/dev/null

wait_for_postgres "$baseline_postgres"
wait_for_postgres "$protected_postgres"

docker run -d --name "$baseline_name" --network "$baseline_network" \
  -p "127.0.0.1:${baseline_port}:8080" \
  -v "${startup_script}:/startup.sh:ro" \
  -e JAVA_OPTS= \
  "$image" bash /startup.sh >/dev/null

docker run -d --name "$protected_name" --network "$protected_network" \
  -p "127.0.0.1:${protected_port}:8080" \
  -v "${startup_script}:/startup.sh:ro" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_OPTS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
  "$image" bash /startup.sh >/dev/null

wait_for_feature_type "$baseline_name" "$baseline_port" "${baseline_dir}/featuretypes.json"
wait_for_feature_type "$protected_name" "$protected_port" "${protected_dir}/featuretypes.json"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17 startup event in GeoServer CVE-2023-25157 protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "GeoServer CVE-2023-25157 protected startup/readiness produced a detection" >&2
  exit 1
fi

baseline_normal_status="$(send_wfs "$baseline_port" "$normal_query" "${baseline_dir}/normal.response")"
if [[ "$baseline_normal_status" != "200" ]]; then
  cat "${baseline_dir}/normal.response" >&2 || true
  echo "baseline GeoServer normal CQL request returned HTTP ${baseline_normal_status}" >&2
  exit 1
fi

baseline_malicious_status="$(send_wfs "$baseline_port" "$malicious_query" "${baseline_dir}/malicious.response")"
if [[ "$baseline_malicious_status" != "200" ]] \
    || ! grep -q 'invalid input syntax for type integer' "${baseline_dir}/malicious.response" \
    || ! grep -q 'PostgreSQL' "${baseline_dir}/malicious.response"; then
  cat "${baseline_dir}/malicious.response" >&2 || true
  echo "baseline GeoServer CVE-2023-25157 request did not reach PostGIS SQL execution; status=${baseline_malicious_status}" >&2
  exit 1
fi

protected_normal_status="$(send_wfs "$protected_port" "$normal_query" "${protected_dir}/normal.response")"
if [[ "$protected_normal_status" != "200" ]]; then
  cat "${protected_dir}/normal.response" >&2 || true
  echo "protected GeoServer normal CQL request returned HTTP ${protected_normal_status}" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "GeoServer CVE-2023-25157 normal CQL request produced a detection" >&2
  exit 1
fi

protected_malicious_status="$(send_wfs "$protected_port" "$malicious_query" "${protected_dir}/malicious.response")"
if [[ "$protected_malicious_status" != "500" ]] \
    || ! grep -q 'Java17RaspBlockException' "${protected_dir}/malicious.response"; then
  cat "${protected_dir}/malicious.response" >&2 || true
  echo "protected GeoServer CVE-2023-25157 request was not blocked; status=${protected_malicious_status}" >&2
  exit 1
fi
if grep -q 'PostgreSQL' "${protected_dir}/malicious.response"; then
  cat "${protected_dir}/malicious.response" >&2
  echo "protected GeoServer CVE-2023-25157 response still leaked PostGIS SQL execution evidence" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java17_request_ogc_filter_sql_injection".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_request_ogc_filter_sql_injection block event for GeoServer CVE-2023-25157" >&2
  exit 1
fi
if grep -q 'SELECT version\|PostgreSQL' "$protected_log"; then
  cat "$protected_log" >&2
  echo "GeoServer CVE-2023-25157 protected log leaked raw SQL payload details" >&2
  exit 1
fi

echo "vulhub GeoServer CVE-2023-25157 Java17 acceptance passed"
