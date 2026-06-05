#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
base_port="${OHMYRASP_VULHUB_STRUTS2_UPLOAD_BASE_PORT:-18520}"
shell_path="/usr/local/tomcat/webapps/ROOT/shell.jsp"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 150); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/index.action" || true)"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose Struts2 upload action at ${port}" >&2
  exit 1
}

upload_shell() {
  local port="$1"
  local output="$2"
  local file_field="$3"
  local filename_field="$4"
  local marker="$5"
  printf '<%% out.println("%s"); %%>\n' "$marker" | curl -sS -o "$output" -w "%{http_code}" \
    -X POST \
    -F "${file_field}=@-;filename=shell.jsp;type=text/plain" \
    -F "${filename_field}=../shell.jsp" \
    "http://127.0.0.1:${port}/index.action" || true
}

run_case() {
  local slug="$1"
  local image="$2"
  local file_field="$3"
  local filename_field="$4"
  local baseline_port="$5"
  local protected_port="$6"
  local algorithm="$7"
  local marker="ohmyrasp-${slug}"
  local baseline_name="ohmyrasp-vulhub-${slug}-baseline"
  local protected_name="ohmyrasp-vulhub-${slug}-protected"
  local baseline_dir="logs/vulhub-struts2-${slug}-java17-baseline"
  local protected_dir="logs/vulhub-struts2-${slug}-java17-protected"
  local protected_log="${protected_dir}/events.jsonl"

  rm -rf "$baseline_dir" "$protected_dir"
  mkdir -p "$baseline_dir" "$protected_dir"
  : > "$protected_log"
  chmod 666 "$protected_log"

  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

  docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
    "$image" >/dev/null

  docker run -d --name "$protected_name" -p "${protected_port}:8080" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e CATALINA_OPTS="-agentlib:jdwp=transport=dt_socket,address=*:5005,server=y,suspend=n -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
    "$image" >/dev/null

  cleanup_case() {
    docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
    docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
    docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
  }

  wait_for "$baseline_name" "$baseline_port"
  wait_for "$protected_name" "$protected_port"

  if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    cleanup_case
    echo "missing Java 17 startup event in ${slug} protected container" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    cleanup_case
    echo "Struts2 ${slug} protected startup produced a detection before the exploit request" >&2
    exit 1
  fi

  local baseline_status
  baseline_status="$(upload_shell "$baseline_port" "${baseline_dir}/upload.response" "$file_field" "$filename_field" "$marker")"
  if [[ "$baseline_status" != "200" ]] || ! docker exec "$baseline_name" test -s "$shell_path"; then
    cat "${baseline_dir}/upload.response" >&2 || true
    cleanup_case
    echo "baseline Struts2 ${slug} did not write shell.jsp" >&2
    exit 1
  fi

  local baseline_shell_status
  baseline_shell_status="$(curl -sS -o "${baseline_dir}/shell.response" -w "%{http_code}" \
    "http://127.0.0.1:${baseline_port}/shell.jsp" || true)"
  if [[ "$baseline_shell_status" != "200" ]] || ! grep -q "$marker" "${baseline_dir}/shell.response"; then
    cat "${baseline_dir}/shell.response" >&2 || true
    cleanup_case
    echo "baseline Struts2 ${slug} shell.jsp did not execute" >&2
    exit 1
  fi

  local protected_status
  protected_status="$(upload_shell "$protected_port" "${protected_dir}/upload.response" "$file_field" "$filename_field" "$marker")"
  if [[ "$protected_status" != "200" ]]; then
    cat "${protected_dir}/upload.response" >&2 || true
    cleanup_case
    echo "protected Struts2 ${slug} upload returned unexpected status ${protected_status}" >&2
    exit 1
  fi
  if docker exec "$protected_name" test -e "$shell_path"; then
    cleanup_case
    echo "protected Struts2 ${slug} wrote shell.jsp despite Java17 RASP" >&2
    exit 1
  fi
  if ! grep -q 'Java17RaspBlockException' "${protected_dir}/upload.response"; then
    cat "${protected_dir}/upload.response" >&2 || true
    cleanup_case
    echo "protected Struts2 ${slug} response did not surface the Java17 RASP block" >&2
    exit 1
  fi
  if ! grep -q "\"algorithm\":\"${algorithm}\".*\"action\":\"block\"" "$protected_log"; then
    cat "$protected_log" >&2
    cleanup_case
    echo "missing ${algorithm} block event for Struts2 ${slug}" >&2
    exit 1
  fi

  cleanup_case
  echo "vulhub Struts2 ${slug} Java17 acceptance passed"
}

run_case "s2-066" "${OHMYRASP_VULHUB_STRUTS2_S2066_IMAGE:-vulhub/struts2:s2-066}" \
  "File" "fileFileName" "$base_port" "$((base_port + 1))" "java17_file_script_write"
run_case "s2-067" "${OHMYRASP_VULHUB_STRUTS2_S2067_IMAGE:-vulhub/struts2:s2-067}" \
  "file" "top.fileFileName" "$((base_port + 2))" "$((base_port + 3))" "java17_file_script_write"
