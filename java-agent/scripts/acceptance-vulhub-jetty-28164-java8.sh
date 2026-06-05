#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_JETTY_28164_IMAGE:-vulhub/jetty:9.4.37}"
src_dir="${OHMYRASP_VULHUB_JETTY_28164_SRC:-/home/ubuntu/vulhub/jetty/CVE-2021-28164/src}"
baseline_name="${OHMYRASP_VULHUB_JETTY_28164_BASELINE_NAME:-ohmyrasp-vulhub-jetty-28164-baseline}"
protected_name="${OHMYRASP_VULHUB_JETTY_28164_PROTECTED_NAME:-ohmyrasp-vulhub-jetty-28164-protected}"
baseline_port="${OHMYRASP_VULHUB_JETTY_28164_BASELINE_PORT:-19131}"
protected_port="${OHMYRASP_VULHUB_JETTY_28164_PROTECTED_PORT:-19132}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-jetty-28164-java8-baseline"
protected_dir="logs/vulhub-jetty-28164-java8-protected"
protected_log="${protected_dir}/events.jsonl"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "127.0.0.1:${baseline_port}:8080" \
  -v "${src_dir}:/opt/jetty/webapps/ROOT:ro" \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "127.0.0.1:${protected_port}:8080" \
  -v "${src_dir}:/opt/jetty/webapps/ROOT:ro" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(curl -sS -o "${dir}/ready-${attempt}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "${name} did not become ready" >&2
  exit 1
}

wait_for "$baseline_name" "$baseline_port" "$baseline_dir"
wait_for "$protected_name" "$protected_port" "$protected_dir"

for attempt in $(seq 1 60); do
  if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    break
  fi
  if [[ "$attempt" == "60" ]]; then
    cat "$protected_log" >&2 || true
    echo "missing Java8 startup event in protected Jetty container" >&2
    exit 1
  fi
  sleep 1
done
if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Jetty protected startup produced a detection before exploit traffic" >&2
  exit 1
fi

curl -sS --path-as-is -o "${baseline_dir}/direct-webinf.body" \
  -D "${baseline_dir}/direct-webinf.headers" -w "%{http_code}" \
  "http://127.0.0.1:${baseline_port}/WEB-INF/web.xml" > "${baseline_dir}/direct.status"
curl -sS --path-as-is -o "${baseline_dir}/exploit-webinf.body" \
  -D "${baseline_dir}/exploit-webinf.headers" -w "%{http_code}" \
  "http://127.0.0.1:${baseline_port}/%2e/WEB-INF/web.xml" > "${baseline_dir}/exploit.status"
printf 'baseline_direct_status=%s\n' "$(cat "${baseline_dir}/direct.status")" >> "${baseline_dir}/attempts.log"
printf 'baseline_exploit_status=%s\n' "$(cat "${baseline_dir}/exploit.status")" >> "${baseline_dir}/attempts.log"
if [[ "$(cat "${baseline_dir}/direct.status")" == "200" ]]; then
  cat "${baseline_dir}/direct-webinf.body" >&2 || true
  echo "baseline direct WEB-INF request should not be accessible" >&2
  exit 1
fi
if [[ "$(cat "${baseline_dir}/exploit.status")" != "200" ]] \
    || ! grep -Fq "<web-app>" "${baseline_dir}/exploit-webinf.body"; then
  cat "${baseline_dir}/exploit-webinf.headers" >&2 || true
  cat "${baseline_dir}/exploit-webinf.body" >&2 || true
  echo "baseline Jetty CVE-2021-28164 request did not disclose WEB-INF/web.xml" >&2
  exit 1
fi

curl -sS --path-as-is -o "${protected_dir}/exploit-webinf.body" \
  -D "${protected_dir}/exploit-webinf.headers" -w "%{http_code}" \
  "http://127.0.0.1:${protected_port}/%2e/WEB-INF/web.xml" > "${protected_dir}/exploit.status" || true
printf 'protected_exploit_status=%s\n' "$(cat "${protected_dir}/exploit.status")" >> "${protected_dir}/attempts.log"
if grep -Fq "<web-app>" "${protected_dir}/exploit-webinf.body"; then
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/exploit-webinf.body" >&2 || true
  echo "protected Jetty CVE-2021-28164 request still disclosed WEB-INF/web.xml" >&2
  exit 1
fi
if ! grep -Eq '"algorithm":"java8_request_path_confusion".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing java8_request_path_confusion block event for Jetty CVE-2021-28164" >&2
  exit 1
fi
printf 'blocked=1\n' >> "${protected_dir}/attempts.log"

echo "vulhub Jetty 9.4.37 CVE-2021-28164 Java8 acceptance passed"
