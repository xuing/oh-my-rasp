#!/bin/sh
# Real-JVM Docker smoke test for all OhMyRASP shirudo Java upatch JARs.
# Tests Temurin 8, 11, 17, 21, and 25 with:
#   - read-only mounted /run/shirudo-java/<jar>
#   - JAVA_TOOL_OPTIONS=-javaagent:/run/shirudo-java/<jar> (no agentArgs)
#   - hostile /tmp/ohmyrasp-control.json containing {"mode":"off"}
#   - zero control/writer background threads
#   - benign file read succeeds
#   - InitialContext.lookup("ldap://127.0.0.1:1389/a") and FileInputStream("/etc/passwd") throw *BlockException
#   - stderr contains detection JSON and NO "hook_latency"
#   - /tmp/ohmyrasp-events.jsonl does NOT exist

set -eu

filter=""

usage() {
	echo "usage: $0 [--target <image-or-track>]" >&2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--target)
		[ $# -ge 2 ] || { usage; exit 2; }
		filter=$2
		shift 2
		;;
	--target=*)
		filter=${1#--target=}
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage
		exit 2
		;;
	esac
done

root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

cat > "$tmp_dir/Probe.java" <<'JAVA'
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;
import javax.naming.InitialContext;

public final class Probe {
  private static final Pattern FORBIDDEN_THREAD =
      Pattern.compile("ohmyrasp-.*-(control|writer|poller)|ohmyrasp-(control|event)-(poller|writer).*");

  public static void main(String[] args) throws Exception {
    boolean jdk25 = args.length > 0 && "jdk25".equals(args[0]);
    checkNoDaemonThreads();
    checkBenignRead();
    checkJndi(jdk25);
    checkFileRead(jdk25);
    if (jdk25) {
      checkBlockedBase64();
    }
    checkNoDaemonThreads();
    System.out.println("PROBE_OK");
  }

  private static void checkNoDaemonThreads() {
    List<String> bad = new ArrayList<String>();
    for (Thread t : Thread.getAllStackTraces().keySet()) {
      String name = t.getName();
      if (name != null && FORBIDDEN_THREAD.matcher(name).matches()) {
        bad.add(name);
      }
    }
    if (!bad.isEmpty()) {
      throw new AssertionError("Forbidden background threads detected: " + bad);
    }
  }

  private static void checkBenignRead() throws Exception {
    FileInputStream in = new FileInputStream("/tmp/benign.txt");
    try {
      ByteArrayOutputStream buf = new ByteArrayOutputStream();
      byte[] chunk = new byte[256];
      int n;
      while ((n = in.read(chunk)) != -1) {
        buf.write(chunk, 0, n);
      }
      String text = new String(buf.toByteArray(), "UTF-8").trim();
      if (!"hello-shirudo".equals(text)) {
        throw new AssertionError("Unexpected benign file content: " + text);
      }
    } finally {
      in.close();
    }
  }

  private static void checkJndi(boolean jdk25) {
    try {
      new InitialContext().lookup("ldap://127.0.0.1:1389/a");
      throw new AssertionError("Expected exception for InitialContext.lookup");
    } catch (Throwable t) {
      if (jdk25) {
        return;
      }
      if (!isBlockException(t)) {
        throw new AssertionError("Expected *BlockException for JNDI lookup, got " + t.getClass().getName(), t);
      }
    }
  }

  private static void checkFileRead(boolean jdk25) {
    FileInputStream in = null;
    try {
      in = new FileInputStream("/etc/passwd");
      if (!jdk25) {
        throw new AssertionError("Expected BlockException for FileInputStream(/etc/passwd)");
      }
    } catch (Throwable t) {
      if (!jdk25 && !isBlockException(t)) {
        throw new AssertionError("Expected *BlockException for /etc/passwd, got " + t.getClass().getName(), t);
      }
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (Throwable ignored) {
        }
      }
    }
  }

  private static void checkBlockedBase64() {
    StringBuilder sb = new StringBuilder(67);
    for (int i = 0; i < 65; i++) {
      sb.append('A');
    }
    sb.append("==");
    try {
      Base64.getDecoder().decode(sb.toString());
      throw new AssertionError("Expected OhMyRaspBlockException for Base64 tail-underflow payload");
    } catch (Throwable t) {
      if (!isBlockException(t)) {
        throw new AssertionError("Expected *BlockException for Base64 payload, got " + t.getClass().getName(), t);
      }
    }
  }

  private static boolean isBlockException(Throwable t) {
    Throwable cur = t;
    while (cur != null) {
      if (cur.getClass().getName().endsWith("BlockException")) {
        return true;
      }
      cur = cur.getCause();
    }
    return false;
  }
}
JAVA

run_case() {
	image=$1
	pkg=$2
	jar_name="${pkg}.jar"
	jar_path="$root/$pkg/$jar_name"

	if [ -n "$filter" ]; then
		case "$image:$pkg" in
		*"$filter"*) ;;
		*) return 0 ;;
		esac
	fi

	if [ ! -f "$jar_path" ]; then
		echo "FAIL: missing $jar_path (run ./deploy/shirudo/build-all.sh --jar-only first)" >&2
		exit 1
	fi

	echo "==> smoke-testing $image with $pkg/$jar_name"
	stdout_file="$tmp_dir/${image##*:}-${pkg}.out"
	stderr_file="$tmp_dir/${image##*:}-${pkg}.err"

	probe_mode="backport"
	if [ "$pkg" = "ohmyrasp-jdk21" ] || [ "$pkg" = "ohmyrasp-jdk25" ]; then
		probe_mode="jdk25"
	fi

	if ! docker run --rm \
		-v "$jar_path:/run/shirudo-java/$jar_name:ro" \
		-v "$tmp_dir/Probe.java:/tmp/Probe.java:ro" \
		"$image" \
		sh -eu -c '
			printf "{\"mode\":\"off\"}\n" > /tmp/ohmyrasp-control.json
			printf "hello-shirudo\n" > /tmp/benign.txt
			mkdir -p /tmp/probe
			env -u JAVA_TOOL_OPTIONS javac -d /tmp/probe /tmp/Probe.java
			export JAVA_TOOL_OPTIONS="-javaagent:/run/shirudo-java/'"$jar_name"'"
			java -cp /tmp/probe Probe "'"$probe_mode"'"
			if [ -e /tmp/ohmyrasp-events.jsonl ]; then
				echo "FAIL: /tmp/ohmyrasp-events.jsonl must not exist" >&2
				exit 1
			fi
		' >"$stdout_file" 2>"$stderr_file"; then
		echo "FAIL: container probe failed for $image ($pkg)" >&2
		cat "$stdout_file" >&2 || true
		cat "$stderr_file" >&2 || true
		exit 1
	fi

	if ! grep -qx "PROBE_OK" "$stdout_file"; then
		echo "FAIL: missing PROBE_OK for $image ($pkg)" >&2
		cat "$stdout_file" >&2
		cat "$stderr_file" >&2
		exit 1
	fi

	python3 - "$stderr_file" "$image" "$pkg" <<'PY'
import json
import sys

stderr_path, image, pkg = sys.argv[1], sys.argv[2], sys.argv[3]
with open(stderr_path, "r", encoding="utf-8", errors="replace") as fh:
    text = fh.read()

if "hook_latency" in text:
    print(f"FAIL: {image} ({pkg}) emitted hook_latency on stderr:\n{text}", file=sys.stderr)
    sys.exit(1)

detections = []
for raw in text.splitlines():
    line = raw.strip()
    if line.startswith("[OHMYRASP]"):
        line = line[len("[OHMYRASP]"):].strip()
    if not line.startswith("{"):
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if obj.get("event") == "ohmyrasp-detection" or obj.get("kind") == "detection":
        detections.append(obj)

if len(detections) < 2:
    print(f"FAIL: {image} ({pkg}) expected >= 2 detection JSON events on stderr, got {len(detections)}:\n{text}", file=sys.stderr)
    sys.exit(1)

hooks = " ".join(str(d.get("hook", "")).lower() for d in detections)
if "jndi" not in hooks and "initialcontext" not in hooks:
    print(f"FAIL: {image} ({pkg}) missing JNDI detection event on stderr: {detections}", file=sys.stderr)
    sys.exit(1)
if pkg in ("ohmyrasp-jdk21", "ohmyrasp-jdk25"):
    if "base64" not in hooks:
        print(f"FAIL: {image} ({pkg}) missing base64 detection event on stderr: {detections}", file=sys.stderr)
        sys.exit(1)
    if not any(d.get("hook") == "base64" and d.get("action") == "block" for d in detections):
        print(f"FAIL: {image} ({pkg}) base64 detection was not recorded with action=block: {detections}", file=sys.stderr)
        sys.exit(1)
else:
    if "file" not in hooks:
        print(f"FAIL: {image} ({pkg}) missing file detection event on stderr: {detections}", file=sys.stderr)
        sys.exit(1)

print(f"OK smoke: {image} + {pkg} ({len(detections)} detection JSON events on stderr)")
PY
}

run_case "eclipse-temurin:8" "ohmyrasp-java8"
run_case "eclipse-temurin:11" "ohmyrasp-java11"
run_case "eclipse-temurin:17" "ohmyrasp-java17"
run_case "eclipse-temurin:21" "ohmyrasp-java17"
run_case "eclipse-temurin:21" "ohmyrasp-jdk21"
run_case "eclipse-temurin:25" "ohmyrasp-jdk25"

echo "ALL SMOKE TESTS PASSED"
