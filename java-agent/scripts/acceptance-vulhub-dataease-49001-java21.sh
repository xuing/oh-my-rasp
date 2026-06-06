#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_DATAEASE_49001_IMAGE:-vulhub/dataease:2.10.7}"
mysql_image="${OHMYRASP_VULHUB_DATAEASE_49001_MYSQL_IMAGE:-mysql:8.4}"
network="${OHMYRASP_VULHUB_DATAEASE_49001_NETWORK:-ohmyrasp-vulhub-dataease49001}"
baseline_db="${OHMYRASP_VULHUB_DATAEASE_49001_BASELINE_DB_NAME:-ohmyrasp-vulhub-dataease49001-db-baseline}"
protected_db="${OHMYRASP_VULHUB_DATAEASE_49001_PROTECTED_DB_NAME:-ohmyrasp-vulhub-dataease49001-db-protected}"
baseline_name="${OHMYRASP_VULHUB_DATAEASE_49001_BASELINE_NAME:-ohmyrasp-vulhub-dataease49001-baseline}"
protected_name="${OHMYRASP_VULHUB_DATAEASE_49001_PROTECTED_NAME:-ohmyrasp-vulhub-dataease49001-protected}"
baseline_port="${OHMYRASP_VULHUB_DATAEASE_49001_BASELINE_PORT:-18724}"
protected_port="${OHMYRASP_VULHUB_DATAEASE_49001_PROTECTED_PORT:-18725}"
host_agent_jar="$(pwd)/agent-java17/build/libs/ohmyrasp-agent-java17.jar"
baseline_dir="logs/vulhub-dataease-2.10.7-cve-2025-49001-java21-baseline"
protected_dir="logs/vulhub-dataease-2.10.7-cve-2025-49001-java21-protected"
protected_log="${protected_dir}/events.jsonl"
user_info_path="/de2api/user/info"

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

wait_for_dataease() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 420); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "404" ]]; then
      return
    fi
    sleep 1
  done
  echo "${name} did not expose DataEase on ${port}" >&2
  exit 1
}

build_wrong_signature_jwt() {
  python3 - <<'PY'
import base64
import hashlib
import hmac
import json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header = {"alg": "HS256"}
payload = {"uid": 1, "oid": 1, "exp": 9739523483}
head = b64url(json.dumps(header, separators=(',', ':')).encode())
body = b64url(json.dumps(payload, separators=(',', ':')).encode())
sig = b64url(hmac.new(b'any-secret-will-do', f'{head}.{body}'.encode(), hashlib.sha256).digest())
print(f'{head}.{body}.{sig}')
PY
}

get_user_info() {
  local port="$1"
  local token="$2"
  local output="$3"
  if [[ -n "$token" ]]; then
    curl -sS -D "${output}.headers" -o "${output}.body" -w "%{http_code}" \
      -H "X-DE-TOKEN: ${token}" \
      "http://127.0.0.1:${port}${user_info_path}" || true
  else
    curl -sS -D "${output}.headers" -o "${output}.body" -w "%{http_code}" \
      "http://127.0.0.1:${port}${user_info_path}" || true
  fi
}

wait_for_dataease "$baseline_name" "$baseline_port"
wait_for_dataease "$protected_name" "$protected_port"

if ! grep -q '"event":"ohmyrasp-java17-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 17-compatible startup event in DataEase protected container" >&2
  exit 1
fi
if ! grep -Eq '"java_version":"21\.' "$protected_log"; then
  cat "$protected_log" >&2
  echo "DataEase protected container did not report a Java 21 runtime" >&2
  exit 1
fi
if ! grep -q '"jwt_hook":"installed"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "DataEase protected container did not report the JWT hook" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "DataEase protected startup produced a detection before the invalid JWT request" >&2
  exit 1
fi

wrong_jwt="$(build_wrong_signature_jwt)"

baseline_no_token_status="$(get_user_info "$baseline_port" "" "${baseline_dir}/no-token")"
if [[ "$baseline_no_token_status" != "401" ]] || ! grep -q 'token is empty' "${baseline_dir}/no-token.body"; then
  cat "${baseline_dir}/no-token.body" >&2 || true
  echo "baseline DataEase no-token user/info request did not return the clean 401" >&2
  exit 1
fi

baseline_wrong_status="$(get_user_info "$baseline_port" "$wrong_jwt" "${baseline_dir}/wrong-signature")"
if [[ "$baseline_wrong_status" != "400" ]]; then
  cat "${baseline_dir}/wrong-signature.body" >&2 || true
  echo "baseline DataEase wrong-signature JWT returned ${baseline_wrong_status}, expected 400" >&2
  exit 1
fi
if ! grep -Fq "Signature%20resulted%20invalid" "${baseline_dir}/wrong-signature.headers"; then
  tr -d '\r' < "${baseline_dir}/wrong-signature.headers" >&2 || true
  echo "baseline DataEase wrong-signature JWT did not expose the continuation signature-failure header" >&2
  exit 1
fi

protected_no_token_status="$(get_user_info "$protected_port" "" "${protected_dir}/no-token")"
if [[ "$protected_no_token_status" != "401" ]] || ! grep -q 'token is empty' "${protected_dir}/no-token.body"; then
  cat "${protected_dir}/no-token.body" >&2 || true
  echo "protected DataEase no-token user/info request did not keep the ordinary 401 behavior" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected DataEase no-token user/info request produced a detection" >&2
  exit 1
fi

protected_wrong_status="$(get_user_info "$protected_port" "$wrong_jwt" "${protected_dir}/wrong-signature")"
if [[ "$protected_wrong_status" != "400" ]]; then
  cat "${protected_dir}/wrong-signature.body" >&2 || true
  echo "protected DataEase wrong-signature JWT returned ${protected_wrong_status}, expected 400" >&2
  exit 1
fi
if ! grep -q '"hook":"com.auth0.jwt.JWTVerifier.verify".*"algorithm":"java17_request_jwt_verification_failure".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java17_request_jwt_verification_failure block event for DataEase CVE-2025-49001" >&2
  exit 1
fi
if ! grep -Fq 'OhMyRASP%20Java%2017%20blocked%20JWT%20verification%20failure%20continuation' "${protected_dir}/wrong-signature.headers"; then
  tr -d '\r' < "${protected_dir}/wrong-signature.headers" >&2 || true
  echo "protected DataEase response did not carry the Java 17 JWT block marker" >&2
  exit 1
fi
if grep -Fq "$wrong_jwt" "$protected_log"; then
  cat "$protected_log" >&2
  echo "protected DataEase JWT verification event leaked the token value" >&2
  exit 1
fi

echo "vulhub DataEase 2.10.7 CVE-2025-49001 Java21 runtime acceptance passed"
