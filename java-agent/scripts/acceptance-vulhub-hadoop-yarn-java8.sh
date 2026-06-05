#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_HADOOP_IMAGE:-vulhub/hadoop:2.8.1}"
baseline_prefix="${OHMYRASP_VULHUB_HADOOP_YARN_BASELINE_PREFIX:-ohmyrasp-vulhub-yarn-baseline}"
protected_prefix="${OHMYRASP_VULHUB_HADOOP_YARN_PROTECTED_PREFIX:-ohmyrasp-vulhub-yarn-protected}"
baseline_port="${OHMYRASP_VULHUB_HADOOP_YARN_BASELINE_PORT:-19121}"
protected_port="${OHMYRASP_VULHUB_HADOOP_YARN_PROTECTED_PORT:-19122}"
marker_path="${OHMYRASP_VULHUB_HADOOP_YARN_MARKER_PATH:-/tmp/ohmyrasp-yarn-success}"
baseline_dir="logs/vulhub-hadoop-yarn-java8-baseline"
protected_dir="logs/vulhub-hadoop-yarn-java8-protected"
protected_log="${protected_dir}/events.jsonl"

copy_artifacts() {
  local prefix="$1"
  local dir="$2"
  for role in namenode datanode resourcemanager nodemanager; do
    local name="${prefix}-${role}"
    if docker inspect "$name" >/dev/null 2>&1; then
      docker logs "$name" > "${dir}/${role}.log" 2>&1 || true
    fi
  done
}

cleanup_prefix() {
  local prefix="$1"
  docker rm -f \
    "${prefix}-nodemanager" \
    "${prefix}-resourcemanager" \
    "${prefix}-datanode" \
    "${prefix}-namenode" >/dev/null 2>&1 || true
  docker network rm "${prefix}-net" >/dev/null 2>&1 || true
}

wait_for_rm() {
  local prefix="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(curl -sS -o "${dir}/ready-${attempt}.json" -w "%{http_code}" \
      "http://127.0.0.1:${port}/ws/v1/cluster/info" 2>/dev/null || true)"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "${prefix}-resourcemanager" >&2 || true
  echo "Hadoop YARN ResourceManager did not become ready on ${port}" >&2
  exit 1
}

wait_for_node_running() {
  local port="$1"
  local dir="$2"
  for attempt in $(seq 1 120); do
    curl -sS -o "${dir}/nodes-${attempt}.json" \
      "http://127.0.0.1:${port}/ws/v1/cluster/nodes" 2>/dev/null || true
    if python3 - "${dir}/nodes-${attempt}.json" <<'PY'
import json
import sys

try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)

nodes = (data.get("nodes") or {}).get("node") or []
if any(node.get("state") == "RUNNING" for node in nodes):
    sys.exit(0)
sys.exit(1)
PY
    then
      printf 'node_running_attempt=%s\n' "$attempt" >> "${dir}/attempts.log"
      return
    fi
    printf 'node_running_attempt=%s pending\n' "$attempt" >> "${dir}/attempts.log"
    sleep 1
  done
  echo "Hadoop YARN NodeManager did not register as RUNNING" >&2
  exit 1
}

start_cluster() {
  local prefix="$1"
  local port="$2"
  local dir="$3"
  local protected="$4"
  local agent_opts="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true"

  cleanup_prefix "$prefix"
  docker network create "${prefix}-net" >/dev/null
  docker run -d --name "${prefix}-namenode" --network "${prefix}-net" \
    -e HDFS_CONF_dfs_namenode_name_dir=file:///hadoop/dfs/name \
    -e CLUSTER_NAME=vulhub \
    -e HDFS_CONF_dfs_replication=1 \
    "$image" /namenode.sh >/dev/null
  docker run -d --name "${prefix}-datanode" --network "${prefix}-net" \
    -e HDFS_CONF_dfs_datanode_data_dir=file:///hadoop/dfs/data \
    -e CORE_CONF_fs_defaultFS=hdfs://"${prefix}-namenode":8020 \
    -e CLUSTER_NAME=vulhub \
    -e HDFS_CONF_dfs_replication=1 \
    "$image" /datanode.sh >/dev/null
  if [[ "$protected" == "true" ]]; then
    docker run -d --name "${prefix}-resourcemanager" --network "${prefix}-net" \
      -p "127.0.0.1:${port}:8088" \
      -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
      -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
      -e "YARN_RESOURCEMANAGER_OPTS=${agent_opts}" \
      -e CORE_CONF_fs_defaultFS=hdfs://"${prefix}-namenode":8020 \
      -e YARN_CONF_yarn_log___aggregation___enable=true \
      "$image" /resourcemanager.sh >/dev/null
  else
    docker run -d --name "${prefix}-resourcemanager" --network "${prefix}-net" \
      -p "127.0.0.1:${port}:8088" \
      -e CORE_CONF_fs_defaultFS=hdfs://"${prefix}-namenode":8020 \
      -e YARN_CONF_yarn_log___aggregation___enable=true \
      "$image" /resourcemanager.sh >/dev/null
  fi
  docker run -d --name "${prefix}-nodemanager" --network "${prefix}-net" \
    -e CORE_CONF_fs_defaultFS=hdfs://"${prefix}-namenode":8020 \
    -e YARN_CONF_yarn_resourcemanager_hostname="${prefix}-resourcemanager" \
    -e YARN_CONF_yarn_log___aggregation___enable=true \
    -e YARN_CONF_yarn_nodemanager_remote___app___log___dir=/app-logs \
    -e YARN_CONF_yarn_nodemanager_local___dirs=/yarn/local \
    -e YARN_CONF_yarn_nodemanager_log___dirs=/yarn/logs \
    -e YARN_CONF_yarn_nodemanager_disk___health___checker_max___disk___utilization___per___disk___percentage=100.0 \
    -e YARN_CONF_yarn_nodemanager_disk___health___checker_min___free___space___per___disk___mb=0 \
    "$image" /nodemanager.sh >/dev/null

  wait_for_rm "$prefix" "$port" "$dir"
  wait_for_node_running "$port" "$dir"
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
  echo "missing Java8 agent startup event for Hadoop YARN ResourceManager" >&2
  exit 1
}

submit_yarn_application() {
  local dir="$1"
  local port="$2"
  local app_name="$3"
  local status
  status="$(curl -sS -o "${dir}/new-application.json" -w "%{http_code}" \
    -X POST "http://127.0.0.1:${port}/ws/v1/cluster/apps/new-application")"
  printf 'new_application_status=%s\n' "$status" >> "${dir}/attempts.log"
  if [[ "$status" != "200" ]]; then
    echo "unexpected new-application status ${status}" >&2
    exit 1
  fi
  local app_id
  app_id="$(python3 - "${dir}/new-application.json" <<'PY'
import json
import sys

print(json.load(open(sys.argv[1], encoding="utf-8"))["application-id"])
PY
)"
  printf 'app_id=%s\n' "$app_id" >> "${dir}/attempts.log"
  python3 - "$app_id" "$app_name" "$marker_path" "${dir}/submit.json" <<'PY'
import json
import sys

app_id, app_name, marker, path = sys.argv[1:5]
payload = {
    "application-id": app_id,
    "application-name": app_name,
    "am-container-spec": {
        "commands": {
            "command": "touch " + marker,
        },
    },
    "application-type": "YARN",
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle)
PY
  status="$(curl -sS -o "${dir}/submit.response" -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    --data-binary "@${dir}/submit.json" \
    "http://127.0.0.1:${port}/ws/v1/cluster/apps" || true)"
  printf 'submit_status=%s\n' "$status" >> "${dir}/attempts.log"
}

run_baseline() {
  start_cluster "$baseline_prefix" "$baseline_port" "$baseline_dir" false
  docker exec "${baseline_prefix}-nodemanager" rm -f "$marker_path" || true
  submit_yarn_application "$baseline_dir" "$baseline_port" "ohmyrasp-yarn-baseline"
  if ! grep -Fq 'submit_status=202' "${baseline_dir}/attempts.log"; then
    cat "${baseline_dir}/submit.response" >&2 || true
    echo "baseline Hadoop YARN application submit did not return HTTP 202" >&2
    exit 1
  fi
  for attempt in $(seq 1 120); do
    printf 'marker_attempt=%s\n' "$attempt" >> "${baseline_dir}/attempts.log"
    if docker exec "${baseline_prefix}-nodemanager" test -f "$marker_path"; then
      printf 'marker_created=1\n' >> "${baseline_dir}/attempts.log"
      copy_artifacts "$baseline_prefix" "$baseline_dir"
      cleanup_prefix "$baseline_prefix"
      return
    fi
    sleep 1
  done
  copy_artifacts "$baseline_prefix" "$baseline_dir"
  tail -n 160 "${baseline_dir}/resourcemanager.log" >&2 || true
  tail -n 160 "${baseline_dir}/nodemanager.log" >&2 || true
  echo "baseline Hadoop YARN did not execute the submitted application marker command" >&2
  exit 1
}

run_protected() {
  start_cluster "$protected_prefix" "$protected_port" "$protected_dir" true
  wait_for_protected_startup
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "Hadoop YARN protected ResourceManager produced a detection before exploit traffic" >&2
    exit 1
  fi
  docker exec "${protected_prefix}-nodemanager" rm -f "$marker_path" || true
  submit_yarn_application "$protected_dir" "$protected_port" "ohmyrasp-yarn-protected"
  for attempt in $(seq 1 45); do
    printf 'protected_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if docker exec "${protected_prefix}-nodemanager" test -f "$marker_path"; then
      cat "$protected_log" >&2 || true
      echo "protected Hadoop YARN still executed the submitted application marker command" >&2
      exit 1
    fi
    if grep -Eq '"algorithm":"java8_request_remote_job_submission".*"action":"block"' "$protected_log"; then
      printf 'blocked=1\n' >> "${protected_dir}/attempts.log"
      copy_artifacts "$protected_prefix" "$protected_dir"
      cleanup_prefix "$protected_prefix"
      return
    fi
    sleep 1
  done
  copy_artifacts "$protected_prefix" "$protected_dir"
  cat "$protected_log" >&2 || true
  cat "${protected_dir}/submit.response" >&2 || true
  echo "missing java8_request_remote_job_submission block event for Hadoop YARN REST submission" >&2
  exit 1
}

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

echo "vulhub Hadoop YARN unauthenticated REST submission Java8 acceptance passed"
