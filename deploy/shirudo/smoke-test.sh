#!/bin/sh
# Real-JVM Docker smoke test for all OhMyRASP shirudo Java upatch JARs.
# Tests Temurin 8, 11, 17, 21, and 25 with:
#   - read-only mounted /run/shirudo-java/<jar>
#   - JAVA_TOOL_OPTIONS=-javaagent:/run/shirudo-java/<jar> (no agentArgs), the way shirudo sets it
#   - hostile /tmp/ohmyrasp-control.json containing {"mode":"off"}
#   - zero control/writer background threads
#   - benign file read succeeds
#   - InitialContext.lookup("ldap://127.0.0.1:1389/a") and FileInputStream("/etc/passwd") throw *BlockException
#   - stderr contains detection JSON and NO "hook_latency"
#   - /tmp/ohmyrasp-events.jsonl does NOT exist
#   - exactly one agent line starts, and it is the line the JAR (or the Java) selects
# Cases:
#   - the universal ohmyrasp.jar alone on every JDK
#   - each per-line JAR on the JDKs it covers
#   - a mixed host: every per-line JAR and the universal JAR in one JAVA_TOOL_OPTIONS, in the name order
#     shirudo writes them, on every JDK. The JVM starts, one line starts, and every option reached the JVM:
#     one launcher line per JAR, so a JAR the JVM dropped would leave fewer lines.
#   - a control for that count: a JAVA_TOOL_OPTIONS of 1024 bytes or more on Java 8 loses its agents without
#     an error (observed: the whole variable is ignored), so a count that falls short would show it.

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
    System.out.println("AGENT_LINE=" + System.getProperty("ohmyrasp.agent.line"));
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

# run_case <image> <label> <probe-mode> <expected-line> <package>...
#   The packages are mounted read-only and named in JAVA_TOOL_OPTIONS in the order given, as shirudo does
#   for the upatches it loads (name order). <probe-mode> is "backport" or "jdk25": what the line that
#   starts must do. <expected-line> is the line that must start (the value of ohmyrasp.agent.line).
run_case() {
	image=$1
	label=$2
	probe_mode=$3
	expected_line=$4
	shift 4

	if [ -n "$filter" ]; then
		case "$image:$label" in
		*"$filter"*) ;;
		*) return 0 ;;
		esac
	fi

	mounts=""
	options=""
	count=0
	for pkg in "$@"; do
		jar_path="$root/$pkg/$pkg.jar"
		if [ ! -f "$jar_path" ]; then
			echo "FAIL: missing $jar_path (run ./deploy/shirudo/build-all.sh --jar-only first)" >&2
			exit 1
		fi
		mounts="$mounts -v $jar_path:/run/shirudo-java/$pkg.jar:ro"
		options="${options:+$options }-javaagent:/run/shirudo-java/$pkg.jar"
		count=$((count + 1))
	done
	# OpenJDK 8 reads at most 1024 bytes of JAVA_TOOL_OPTIONS and drops the rest without an error.
	options_bytes=$(printf %s "$options" | wc -c)
	if [ "$options_bytes" -ge 1024 ]; then
		echo "FAIL: JAVA_TOOL_OPTIONS for $label is $options_bytes bytes; OpenJDK 8 keeps only 1024" >&2
		exit 1
	fi

	echo "==> smoke-testing $image with $label ($count package(s), JAVA_TOOL_OPTIONS $options_bytes bytes)"
	stdout_file="$tmp_dir/${image##*:}-${label}.out"
	stderr_file="$tmp_dir/${image##*:}-${label}.err"

	# shellcheck disable=SC2086 # $mounts is a list of -v arguments without spaces inside them
	if ! docker run --rm \
		$mounts \
		-v "$tmp_dir/Probe.java:/tmp/Probe.java:ro" \
		"$image" \
		sh -eu -c '
			printf "{\"mode\":\"off\"}\n" > /tmp/ohmyrasp-control.json
			printf "hello-shirudo\n" > /tmp/benign.txt
			mkdir -p /tmp/probe
			env -u JAVA_TOOL_OPTIONS javac -d /tmp/probe /tmp/Probe.java
			export JAVA_TOOL_OPTIONS="'"$options"'"
			java -cp /tmp/probe Probe "'"$probe_mode"'"
			if [ -e /tmp/ohmyrasp-events.jsonl ]; then
				echo "FAIL: /tmp/ohmyrasp-events.jsonl must not exist" >&2
				exit 1
			fi
		' >"$stdout_file" 2>"$stderr_file"; then
		echo "FAIL: container probe failed for $image ($label)" >&2
		cat "$stdout_file" >&2 || true
		cat "$stderr_file" >&2 || true
		exit 1
	fi

	if ! grep -qx "PROBE_OK" "$stdout_file"; then
		echo "FAIL: missing PROBE_OK for $image ($label)" >&2
		cat "$stdout_file" >&2
		cat "$stderr_file" >&2
		exit 1
	fi
	if ! grep -qx "AGENT_LINE=$expected_line" "$stdout_file"; then
		echo "FAIL: $image ($label) expected line $expected_line, the JVM reports: $(grep '^AGENT_LINE=' "$stdout_file")" >&2
		cat "$stderr_file" >&2
		exit 1
	fi

	python3 - "$stderr_file" "$image" "$label" "$probe_mode" "$count" <<'PY'
import json
import sys

stderr_path, image, label, probe_mode, packages = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
with open(stderr_path, "r", encoding="utf-8", errors="replace") as fh:
    text = fh.read()

if "hook_latency" in text:
    print(f"FAIL: {image} ({label}) emitted hook_latency on stderr:\n{text}", file=sys.stderr)
    sys.exit(1)

detections = []
starts = []    # the one line that started writes one of these
skipped = []   # a JAR that started nothing: another line was active, or none fits
failed = []
for raw in text.splitlines():
    line = raw.strip()
    if line.startswith("[OHMYRASP] agent started"):
        starts.append(line)
        continue
    if line.startswith("[OHMYRASP]"):
        line = line[len("[OHMYRASP]"):].strip()
    if not line.startswith("{"):
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    event = obj.get("event")
    if event == "ohmyrasp-detection" or obj.get("kind") == "detection":
        detections.append(obj)
    elif event and event.startswith("ohmyrasp-java") and event.endswith("-agent-start"):
        starts.append(line)
    elif event == "ohmyrasp-agent-skipped":
        skipped.append(obj)
    elif event == "ohmyrasp-agent-start-failed":
        failed.append(obj)

if failed:
    print(f"FAIL: {image} ({label}) a line failed to start: {failed}", file=sys.stderr)
    sys.exit(1)
if len(starts) != 1:
    print(f"FAIL: {image} ({label}) expected exactly one agent line to start, got {len(starts)}:\n{text}", file=sys.stderr)
    sys.exit(1)
# Every JAR in JAVA_TOOL_OPTIONS reached its launcher: the one that started, and one skip line for each of
# the others. A JAR the JVM dropped (OpenJDK 8 past 1024 bytes) would leave fewer lines.
if len(starts) + len(skipped) != packages:
    print(f"FAIL: {image} ({label}) {packages} package(s) in JAVA_TOOL_OPTIONS but {len(starts)} start and "
          f"{len(skipped)} skip line(s):\n{text}", file=sys.stderr)
    sys.exit(1)

if len(detections) < 2:
    print(f"FAIL: {image} ({label}) expected >= 2 detection JSON events on stderr, got {len(detections)}:\n{text}", file=sys.stderr)
    sys.exit(1)

hooks = " ".join(str(d.get("hook", "")).lower() for d in detections)
if "jndi" not in hooks and "initialcontext" not in hooks:
    print(f"FAIL: {image} ({label}) missing JNDI detection event on stderr: {detections}", file=sys.stderr)
    sys.exit(1)
if probe_mode == "jdk25":
    if "base64" not in hooks:
        print(f"FAIL: {image} ({label}) missing base64 detection event on stderr: {detections}", file=sys.stderr)
        sys.exit(1)
    if not any(d.get("hook") == "base64" and d.get("action") == "block" for d in detections):
        print(f"FAIL: {image} ({label}) base64 detection was not recorded with action=block: {detections}", file=sys.stderr)
        sys.exit(1)
else:
    if "file" not in hooks:
        print(f"FAIL: {image} ({label}) missing file detection event on stderr: {detections}", file=sys.stderr)
        sys.exit(1)

print(f"OK smoke: {image} + {label} (start: {starts[0][:90]}; {len(skipped)} skipped, {len(detections)} detection JSON events on stderr)")
PY
}

# The universal package alone: each JVM gets the line that fits it.
run_case "eclipse-temurin:8" "ohmyrasp" backport java8 ohmyrasp
run_case "eclipse-temurin:11" "ohmyrasp" backport java11 ohmyrasp
run_case "eclipse-temurin:17" "ohmyrasp" backport java17 ohmyrasp
run_case "eclipse-temurin:21" "ohmyrasp" jdk25 primary ohmyrasp
run_case "eclipse-temurin:25" "ohmyrasp" jdk25 primary ohmyrasp

# One package per line, on the JDKs it covers.
run_case "eclipse-temurin:8" "ohmyrasp-java8" backport java8 ohmyrasp-java8
run_case "eclipse-temurin:11" "ohmyrasp-java11" backport java11 ohmyrasp-java11
run_case "eclipse-temurin:17" "ohmyrasp-java17" backport java17 ohmyrasp-java17
run_case "eclipse-temurin:21" "ohmyrasp-java17" backport java17 ohmyrasp-java17
run_case "eclipse-temurin:21" "ohmyrasp-jdk21" jdk25 primary ohmyrasp-jdk21
run_case "eclipse-temurin:25" "ohmyrasp-jdk25" jdk25 primary ohmyrasp-jdk25

# A mixed host: every package at once, in the order shirudo writes them (byte order of the names).
# `ohmyrasp` comes first, so its launcher picks the line for the JVM and the other five JARs skip.
all_packages=$(cd "$root" && for d in ohmyrasp ohmyrasp-java8 ohmyrasp-java11 ohmyrasp-java17 ohmyrasp-jdk21 ohmyrasp-jdk25; do echo "$d"; done | LC_ALL=C sort)
# shellcheck disable=SC2086 # one package name per word
run_case "eclipse-temurin:8" "mixed" backport java8 $all_packages
# shellcheck disable=SC2086
run_case "eclipse-temurin:11" "mixed" backport java11 $all_packages
# shellcheck disable=SC2086
run_case "eclipse-temurin:17" "mixed" backport java17 $all_packages
# shellcheck disable=SC2086
run_case "eclipse-temurin:21" "mixed" jdk25 primary $all_packages
# shellcheck disable=SC2086
run_case "eclipse-temurin:25" "mixed" jdk25 primary $all_packages

# Control: OpenJDK 8 handles a JAVA_TOOL_OPTIONS of 1024 bytes or more without an error (JDK-8288483). Pad the
# mixed host's options to 1024 bytes: the launcher lines the mixed case counts must be gone.
run_java8_limit_control() {
	if [ -n "$filter" ]; then
		case "eclipse-temurin:8:limit" in
		*"$filter"*) ;;
		*) return 0 ;;
		esac
	fi
	mounts=""
	options=""
	for pkg in "$@"; do
		mounts="$mounts -v $root/$pkg/$pkg.jar:/run/shirudo-java/$pkg.jar:ro"
		options="${options:+$options }-javaagent:/run/shirudo-java/$pkg.jar"
	done
	short=$(printf %s "$options" | wc -c)
	pad_bytes=$((1024 - short - 7))
	pad=$(head -c "$pad_bytes" /dev/zero | tr '\0' x)
	padded="-Dpad=$pad $options"
	padded_bytes=$(printf %s "$padded" | wc -c)
	echo "==> smoke-testing eclipse-temurin:8 limit control (JAVA_TOOL_OPTIONS $padded_bytes bytes)"
	# shellcheck disable=SC2086
	lines=$(docker run --rm $mounts eclipse-temurin:8 sh -c "JAVA_TOOL_OPTIONS='$padded' java -version" 2>&1 \
		| grep -c '"event":"ohmyrasp' || true)
	if [ "$padded_bytes" -lt 1024 ] || [ "$lines" -ne 0 ]; then
		echo "FAIL: Java 8 with a $padded_bytes-byte JAVA_TOOL_OPTIONS wrote $lines OhMyRASP line(s); expected the JVM to lose every agent." >&2
		echo "      If OpenJDK 8 changed, review the Java 8 limit text in deploy/shirudo/gen-readmes.py." >&2
		exit 1
	fi
	echo "OK smoke: eclipse-temurin:8 limit control ($padded_bytes bytes: $lines of $# OhMyRASP lines reached the JVM)"
}
# shellcheck disable=SC2086
run_java8_limit_control $all_packages

echo "ALL SMOKE TESTS PASSED"
