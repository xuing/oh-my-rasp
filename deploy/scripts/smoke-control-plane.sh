#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ -f "$REPO_ROOT/.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$REPO_ROOT/.env"
  set +a
fi

API_URL="${API_URL:-http://localhost:${API_PORT:-18090}}"
WEB_URL="${WEB_URL:-http://localhost:${WEB_PORT:-18091}}"
ADMIN_EMAIL="${ADMIN_EMAIL:-${OHMYRASP_BOOTSTRAP_ADMIN_EMAIL:-admin@ohmyrasp.local}}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-${OHMYRASP_BOOTSTRAP_ADMIN_PASSWORD:-change-me}}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

json_get() {
  local file="$1"
  local expr="$2"
  python3 - "$file" "$expr" <<'PY'
import json
import sys

path = sys.argv[2].split(".")
with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
for part in path:
    if part.isdigit():
        value = value[int(part)]
    else:
        value = value[part]
if isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":")))
else:
    print(value)
PY
}

request_json() {
  local method="$1"
  local path="$2"
  local output="$3"
  local body=""
  shift 3
  if [[ $# -gt 0 ]]; then
    body="$1"
    shift
  fi

  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" "$API_URL$path" \
      -H "Accept: application/json" \
      -H "Content-Type: application/json" \
      "$@" \
      --data "$body" \
      > "$output"
  else
    curl -fsS -X "$method" "$API_URL$path" \
      -H "Accept: application/json" \
      "$@" \
      > "$output"
  fi
}

require_non_empty() {
  local label="$1"
  local value="$2"
  if [[ -z "$value" || "$value" == "null" ]]; then
    echo "missing $label" >&2
    exit 1
  fi
}

echo "Checking health endpoints"
curl -fsS "$API_URL/healthz" > "$tmp_dir/health.json"
curl -fsS "$API_URL/readyz" > "$tmp_dir/ready.json"
curl -fsS "$API_URL/metrics" | grep -q "ohmyrasp_api_up 1"
curl -fsS "$WEB_URL/" | grep -q "OhMyRasp Control"

echo "Logging in"
request_json POST /api/v1/auth/login "$tmp_dir/login.json" "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}"
token="$(json_get "$tmp_dir/login.json" session.token)"
require_non_empty "session token" "$token"
auth=(-H "Authorization: Bearer $token")

request_json GET /api/v1/me "$tmp_dir/me.json" "" "${auth[@]}"
require_non_empty "current user" "$(json_get "$tmp_dir/me.json" user.email)"
request_json GET /api/v1/system/edition "$tmp_dir/edition.json" "" "${auth[@]}"
if [[ "$(json_get "$tmp_dir/edition.json" edition)" != "oss_self_hosted" || "$(json_get "$tmp_dir/edition.json" license_required)" != "False" ]]; then
  echo "unexpected edition status" >&2
  exit 1
fi

suffix="$(date -u +%Y%m%d%H%M%S)"
app_name="Smoke App $suffix"

echo "Creating application, environment, policy, and Agent"
request_json POST /api/v1/applications "$tmp_dir/app.json" "{\"name\":\"$app_name\",\"description\":\"Disposable smoke-test application\"}" "${auth[@]}"
app_id="$(json_get "$tmp_dir/app.json" id)"
app_secret="$(json_get "$tmp_dir/app.json" secret)"
require_non_empty "application id" "$app_id"
require_non_empty "application secret" "$app_secret"

request_json POST "/api/v1/applications/$app_id/environments" "$tmp_dir/env.json" '{"name":"smoke","kind":"test"}' "${auth[@]}"
env_id="$(json_get "$tmp_dir/env.json" id)"
require_non_empty "environment id" "$env_id"

request_json POST "/api/v1/applications/$app_id/secret/rotate" "$tmp_dir/app-secret.json" '{}' "${auth[@]}"
app_secret="$(json_get "$tmp_dir/app-secret.json" secret)"
require_non_empty "rotated application secret" "$app_secret"
app_auth=(-H "X-OhMyRasp-App-ID: $app_id" -H "X-OhMyRasp-App-Secret: $app_secret")

request_json POST /api/v1/policies "$tmp_dir/policy.json" "{\"name\":\"Smoke Policy $suffix\",\"description\":\"Disposable smoke-test policy\"}" "${auth[@]}"
policy_id="$(json_get "$tmp_dir/policy.json" id)"
require_non_empty "policy id" "$policy_id"

request_json POST "/api/v1/policies/$policy_id/versions" "$tmp_dir/policy-version.json" '{"rules":[{"name":"Block SQL smoke","hook":"sql","algorithm":"sql_userinput","action":"block","severity":"high","expression":"'\'' OR '\''1'\''='\''1","tags":["smoke"],"description":"Smoke test rule"}]}' "${auth[@]}"
request_json PUT "/api/v1/policies/$policy_id/versions/1/rules" "$tmp_dir/policy-version-update.json" '{"rules":[{"name":"Block SQL smoke edited","hook":"sql","algorithm":"sql_userinput","action":"block","severity":"high","expression":"'\'' OR '\''1'\''='\''1","tags":["smoke","edited"],"description":"Smoke test edited rule"}]}' "${auth[@]}"
if [[ "$(json_get "$tmp_dir/policy-version-update.json" versions.0.rules.0.name)" != "Block SQL smoke edited" ]]; then
  echo "policy draft rule update did not persist" >&2
  exit 1
fi
request_json POST "/api/v1/policies/$policy_id/rollout" "$tmp_dir/rollout.json" '{"version":1,"canary_percent":100}' "${auth[@]}"

request_json POST /api/v1/agents/register "$tmp_dir/agent.json" '{"environment_id":"'"$env_id"'","hostname":"smoke-agent-1","runtime":"java","version":"1.0.0"}' \
  -H "X-OhMyRasp-App-ID: $app_id" \
  -H "X-OhMyRasp-App-Secret: $app_secret"
agent_id="$(json_get "$tmp_dir/agent.json" id)"
require_non_empty "agent id" "$agent_id"

request_json POST "/api/v1/agents/$agent_id/heartbeat" "$tmp_dir/heartbeat.json" '{"status":"online"}' "${app_auth[@]}"
request_json GET "/api/v1/agents/$agent_id/policy" "$tmp_dir/agent-policy.json" "" "${app_auth[@]}"
require_non_empty "agent policy version" "$(json_get "$tmp_dir/agent-policy.json" version)"

echo "Ingesting event and dependency telemetry"
request_json POST /api/v1/events/attack "$tmp_dir/event.json" '{"application_id":"'"$app_id"'","environment_id":"'"$env_id"'","agent_id":"'"$agent_id"'","policy_id":"'"$policy_id"'","policy_version":1,"hook":"sql","algorithm":"sql_userinput","severity":"critical","message":"Smoke SQL tautology blocked","attributes":{"path":"/smoke"}}' "${app_auth[@]}"
request_json POST /api/v1/events/hook "$tmp_dir/hook-event.json" '{"application_id":"'"$app_id"'","environment_id":"'"$env_id"'","agent_id":"'"$agent_id"'","policy_id":"'"$policy_id"'","policy_version":1,"hook":"servlet","algorithm":"request_trace","severity":"low","message":"Smoke Hook event","attributes":{"latency_us":1200}}' "${app_auth[@]}"
request_json POST /api/v1/events/performance "$tmp_dir/performance-event.json" '{"application_id":"'"$app_id"'","environment_id":"'"$env_id"'","agent_id":"'"$agent_id"'","policy_id":"'"$policy_id"'","policy_version":1,"hook":"sql","algorithm":"overhead_sample","severity":"low","message":"Smoke performance sample","attributes":{"cpu_overhead_pct":1.2}}' "${app_auth[@]}"
request_json POST /api/v1/events/crash "$tmp_dir/crash-event.json" '{"application_id":"'"$app_id"'","environment_id":"'"$env_id"'","agent_id":"'"$agent_id"'","policy_id":"'"$policy_id"'","policy_version":1,"hook":"transform","algorithm":"crash_report","severity":"high","message":"Smoke crash report","attributes":{"exception":"SmokeException"}}' "${app_auth[@]}"
request_json GET "/api/v1/events/attack?application_id=$app_id&environment_id=$env_id&agent_id=$agent_id&policy_id=$policy_id&severity=critical&hook=sql&limit=1" "$tmp_dir/event-filtered.json" "" "${auth[@]}"
attack_event_id="$(json_get "$tmp_dir/event-filtered.json" items.0.id)"
require_non_empty "filtered attack event" "$attack_event_id"
request_json POST /api/v1/events/recycle-bin/delete "$tmp_dir/event-recycle-delete.json" '{"ids":["'"$attack_event_id"'"]}' "${auth[@]}"
if [[ "$(json_get "$tmp_dir/event-recycle-delete.json" count)" != "1" ]]; then
  echo "event recycle delete did not affect one event" >&2
  exit 1
fi
request_json GET "/api/v1/events/recycle-bin?type=attack&application_id=$app_id&limit=1" "$tmp_dir/event-recycle-bin.json" "" "${auth[@]}"
if [[ "$(json_get "$tmp_dir/event-recycle-bin.json" items.0.id)" != "$attack_event_id" ]]; then
  echo "event recycle bin did not contain deleted event" >&2
  exit 1
fi
request_json POST /api/v1/events/recycle-bin/restore "$tmp_dir/event-recycle-restore.json" '{"ids":["'"$attack_event_id"'"]}' "${auth[@]}"
if [[ "$(json_get "$tmp_dir/event-recycle-restore.json" count)" != "1" ]]; then
  echo "event recycle restore did not affect one event" >&2
  exit 1
fi
request_json POST /api/v1/dependencies "$tmp_dir/dependency.json" '{"application_id":"'"$app_id"'","agent_id":"'"$agent_id"'","name":"smoke-lib","version":"1.0.0","ecosystem":"maven","package_path":"com/example/smoke-lib/1.0.0/smoke-lib-1.0.0.jar","licenses":["Apache-2.0"],"vulnerabilities":[{"id":"CVE-2026-SMOKE","severity":"critical","cvss":9.1,"known_exploited":true,"fixed_version":"1.0.1"}]}' "${app_auth[@]}"
request_json GET "/api/v1/dependencies?application_id=$app_id&agent_id=$agent_id&name=smoke-lib&ecosystem=maven&vulnerability_severity=critical&limit=1" "$tmp_dir/dependency-filtered.json" "" "${auth[@]}"
require_non_empty "filtered dependency" "$(json_get "$tmp_dir/dependency-filtered.json" items.0.id)"
require_non_empty "filtered dependency package path" "$(json_get "$tmp_dir/dependency-filtered.json" items.0.package_path)"
require_non_empty "filtered dependency vulnerability" "$(json_get "$tmp_dir/dependency-filtered.json" items.0.vulnerabilities.0.id)"
request_json POST /api/v1/baseline-findings "$tmp_dir/baseline.json" '{"application_id":"'"$app_id"'","environment_id":"'"$env_id"'","agent_id":"'"$agent_id"'","check_id":"jvm.security_manager","title":"JVM security manager disabled","category":"runtime","severity":"medium","status":"warning","resource":"'"$agent_id"'","remediation":"Enable explicit policy controls before production rollout.","attributes":{"runtime":"java"}}' "${app_auth[@]}"
request_json GET "/api/v1/baseline-findings?application_id=$app_id&environment_id=$env_id&agent_id=$agent_id&severity=medium&status=warning&category=runtime&limit=1" "$tmp_dir/baseline-filtered.json" "" "${auth[@]}"
require_non_empty "filtered baseline finding" "$(json_get "$tmp_dir/baseline-filtered.json" items.0.id)"
require_non_empty "filtered baseline check" "$(json_get "$tmp_dir/baseline-filtered.json" items.0.check_id)"
request_json GET "/api/v1/analytics/observability?application_id=$app_id&policy_id=$policy_id" "$tmp_dir/observability-filtered.json" "" "${auth[@]}"
request_json POST /api/v1/maintenance/cleanup "$tmp_dir/maintenance-cleanup-preview.json" '{"application_id":"'"$app_id"'","before":"1970-01-01T00:00:00Z","dry_run":true}' "${auth[@]}"
if [[ "$(json_get "$tmp_dir/maintenance-cleanup-preview.json" dry_run)" != "True" && "$(json_get "$tmp_dir/maintenance-cleanup-preview.json" dry_run)" != "true" ]]; then
  echo "maintenance cleanup preview did not run in dry-run mode" >&2
  exit 1
fi
request_json POST /api/v1/maintenance/cleanup "$tmp_dir/maintenance-cleanup-apply.json" '{"application_id":"'"$app_id"'","before":"1970-01-01T00:00:00Z","dry_run":false,"confirmation":"CLEAR_OPERATIONAL_DATA"}' "${auth[@]}"

echo "Reporting daemon workload inventory"
request_json POST /api/v1/daemon/token/reset "$tmp_dir/daemon-token.json" '{}' "${auth[@]}"
daemon_token="$(json_get "$tmp_dir/daemon-token.json" access_token)"
require_non_empty "daemon access token" "$daemon_token"
daemon_auth=(-H "X-OhMyRasp-Daemon-Token: $daemon_token")
legacy_daemon_auth=(-H "X-Auth-Token: $daemon_token")

request_json GET "/api/v1/daemon/app?app_id=$app_id" "$tmp_dir/daemon-app.json" "" "${daemon_auth[@]}"
if [[ "$(json_get "$tmp_dir/daemon-app.json" application_id)" != "$app_id" ]]; then
  echo "unexpected daemon app lookup" >&2
  exit 1
fi
require_non_empty "daemon app secret" "$(json_get "$tmp_dir/daemon-app.json" application_secret)"
request_json GET "/v1/service/app/get?appId=$app_id" "$tmp_dir/daemon-app-legacy.json" "" "${legacy_daemon_auth[@]}"
require_non_empty "legacy daemon app secret" "$(json_get "$tmp_dir/daemon-app-legacy.json" data.secret)"

artifact_version="smoke-$suffix"
python3 - "$tmp_dir/agent-artifact-upload.json" "$artifact_version" <<'PY'
import base64
import io
import json
import sys
import zipfile

output, version = sys.argv[1], sys.argv[2]
buffer = io.BytesIO()
with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
    archive.writestr("README.txt", f"OhMyRasp smoke artifact {version}\n")
body = {
    "filename": f"smoke-agent-{version}.zip",
    "language": "java",
    "system_type": "linux",
    "language_version": version,
    "content_base64": base64.b64encode(buffer.getvalue()).decode(),
}
with open(output, "w", encoding="utf-8") as handle:
    json.dump(body, handle, separators=(",", ":"))
PY
request_json POST /api/v1/agent-artifacts "$tmp_dir/agent-artifact-upload-response.json" "$(<"$tmp_dir/agent-artifact-upload.json")" "${auth[@]}"
uploaded_artifact_md5="$(json_get "$tmp_dir/agent-artifact-upload-response.json" md5)"
require_non_empty "uploaded agent artifact md5" "$uploaded_artifact_md5"
request_json GET "/api/v1/daemon/artifacts/agent/info?app_id=$app_id&language=java&system_type=linux&language_version=$artifact_version" "$tmp_dir/daemon-artifact-info.json" "" "${daemon_auth[@]}"
artifact_md5="$(json_get "$tmp_dir/daemon-artifact-info.json" md5)"
require_non_empty "daemon artifact md5" "$artifact_md5"
if [[ "$artifact_md5" != "$uploaded_artifact_md5" ]]; then
  echo "daemon artifact did not resolve uploaded package: $artifact_md5 != $uploaded_artifact_md5" >&2
  exit 1
fi
curl -fsS "$API_URL/api/v1/daemon/artifacts/agent?app_id=$app_id&language=java&system_type=linux&language_version=$artifact_version" "${daemon_auth[@]}" > "$tmp_dir/daemon-agent.zip"
download_md5="$(python3 - "$tmp_dir/daemon-agent.zip" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as handle:
    print(hashlib.md5(handle.read()).hexdigest())
PY
)"
if [[ "$download_md5" != "$artifact_md5" ]]; then
  echo "daemon artifact md5 mismatch: $download_md5 != $artifact_md5" >&2
  exit 1
fi

request_json POST /api/v1/daemon/workloads/report "$tmp_dir/daemon-workloads.json" '{"node_name":"smoke-node-'"$suffix"'","workloads":[{"type":"process","pid":4242,"cmdline":["/usr/bin/java","-jar","smoke.jar"]},{"type":"container","container_id":"smoke-container-'"$suffix"'","container_name":"smoke-container","image_tag":"smoke:latest"}]}' "${daemon_auth[@]}"
workload_id="$(json_get "$tmp_dir/daemon-workloads.json" items.0.id)"
require_non_empty "daemon workload id" "$workload_id"
request_json POST "/api/v1/daemon/workloads/$workload_id/bind" "$tmp_dir/daemon-bind.json" '{"application_id":"'"$app_id"'"}' "${auth[@]}"
request_json GET /api/v1/daemon/commands "$tmp_dir/daemon-commands.json" "" "${daemon_auth[@]}"
command_app_id="$(json_get "$tmp_dir/daemon-commands.json" items.0.application_id)"
require_non_empty "daemon command application id" "$command_app_id"
if [[ "$command_app_id" != "$app_id" ]]; then
  echo "unexpected daemon command application id: $command_app_id" >&2
  exit 1
fi
require_non_empty "daemon command app secret" "$(json_get "$tmp_dir/daemon-commands.json" items.0.application_secret)"
require_non_empty "daemon command workload id" "$(json_get "$tmp_dir/daemon-commands.json" items.0.workloads.0.id)"
request_json POST /api/v1/daemon/injection-reports "$tmp_dir/daemon-injection.json" '{"workload_id":"'"$workload_id"'","status":"failed","error":"smoke injection permission denied","helper_id":"smoke-helper-'"$suffix"'","helper_version":"1.0.0"}' "${daemon_auth[@]}"
if [[ "$(json_get "$tmp_dir/daemon-injection.json" injection_status)" != "failed" ]]; then
  echo "unexpected daemon injection status" >&2
  exit 1
fi
request_json POST "/api/v1/daemon/workloads/$workload_id/unbind" "$tmp_dir/daemon-unbind.json" '{}' "${auth[@]}"

echo "Checking authenticated read routes"
for route in \
  /api/v1/daemon/token \
  /api/v1/daemon/workloads \
  /api/v1/agent-artifacts \
  /api/v1/applications \
  /api/v1/agents \
  /api/v1/policies \
  /api/v1/events/attack \
  /api/v1/events/hook \
  /api/v1/events/performance \
  /api/v1/events/crash \
  /api/v1/dependencies \
  /api/v1/baseline-findings \
  /api/v1/analytics/overview \
  /api/v1/analytics/observability \
  /api/v1/system-settings \
  /api/v1/alert-rules \
  /api/v1/alert-deliveries \
  /api/v1/audit-logs \
  /api/v1/users
do
  request_json GET "$route" "$tmp_dir/$(echo "$route" | tr / _).json" "" "${auth[@]}"
done

echo "Checking operational metrics"
curl -fsS "$API_URL/metrics" > "$tmp_dir/metrics.txt"
grep -q "ohmyrasp_agents_total" "$tmp_dir/metrics.txt"
grep -q "ohmyrasp_agent_last_seen_timestamp_seconds" "$tmp_dir/metrics.txt"
grep -q "ohmyrasp_event_ingest_lag_seconds" "$tmp_dir/metrics.txt"
grep -q "ohmyrasp_policy_pull_latency_seconds_count" "$tmp_dir/metrics.txt"

echo "Smoke test passed"
