#!/usr/bin/env bash
# Incremental JDK 25 detector checks against the current checkout.
set -euo pipefail

usage() {
  echo "Usage: $0 [--tests Gradle-test-filter] [file-delete|file-read|file-streams|http-transport|jmx-dispatch|jwt-verification|multipart-archive|mybatis-mapping|process-launch|serial-filter|sqlite-identifiers|write-namespace|xml-resolution [probe options]]"
  echo "The benign corpus always runs. Unit tests default to the whole primary module."
}

tests=""
if [[ "${1:-}" == --tests ]]; then
  if [[ -z "${2:-}" ]]; then usage >&2; exit 2; fi
  tests=$2
  shift 2
fi
case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  ""|file-delete|file-read|file-streams|http-transport|jmx-dispatch|jwt-verification|multipart-archive|mybatis-mapping|process-launch|serial-filter|sqlite-identifiers|write-namespace|xml-resolution) ;;
  *) usage >&2; exit 2 ;;
esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
image=$(awk '$1 == "FROM" && $2 ~ /^gradle:/ {print $2; exit}' "$root/Dockerfile")
uid=$(id -u)
runtime_dir=${XDG_RUNTIME_DIR:-/run/user/$uid}
if [[ -d "$runtime_dir" && -O "$runtime_dir" && -w "$runtime_dir" ]]; then
  cache_base="$runtime_dir/ohmyrasp-jdk25"
else
  cache_base="${XDG_CACHE_HOME:-$HOME/.cache}/ohmyrasp-jdk25"
fi
checkout=$(printf '%s' "$root" | sha256sum | cut -c1-16)
state="${RASP_JDK25_CACHE:-$cache_base}/$checkout"
umask 077
mkdir -p "$state"
state=$(cd "$state" && pwd -P)
echo "JDK 25 build cache: $state"
cache_relative=""
if [[ "$state" == "$root/"* ]]; then
  cache_relative=${state#"$root"/}
  cache_relative=${cache_relative%/*}
fi

# Keep this checkout's published jar stable while a probe is reading it.
exec 9>"$state/check.lock"
flock 9
docker run --rm -i --read-only --tmpfs /tmp:rw,exec \
  -u "$uid:$(id -g)" -e GRADLE_USER_HOME=/state/gradle -e "CACHE_RELATIVE=$cache_relative" -e "TEST_FILTER=$tests" \
  -v "$root:/workspace:ro" -v "$state:/state" -w /workspace \
  "$image" bash -s -- "$@" <<'CONTAINER'
set -euo pipefail
# Gradle requires writable project directories. Stage source in memory while
# keeping persistent task outputs and dependency caches outside the checkout.
mkdir /tmp/project
exclude_state=()
if [[ -n "$CACHE_RELATIVE" ]]; then exclude_state=(--exclude="./$CACHE_RELATIVE"); fi
tar --format=posix --anchored --no-wildcards "${exclude_state[@]}" \
  --exclude=./build --exclude=./.gradle --exclude=./logs \
  --wildcards --no-wildcards-match-slash --exclude='./*/build' --exclude='./*/.gradle' \
  -cf - . | tar -C /tmp/project -xf -
cd /tmp/project
cat >/tmp/build-output.gradle <<'GRADLE'
gradle.beforeProject { project ->
    project.layout.buildDirectory.set(new File("/state/build", project.name))
}
GRADLE

test_options=()
if [[ -n "$TEST_FILTER" ]]; then test_options=(--tests "$TEST_FILTER"); fi
gradle --no-daemon --no-problems-report --configuration-cache \
  --project-cache-dir /state/project -I /tmp/build-output.gradle \
  :agent-jdk25:test "${test_options[@]}" :agent-jdk25:agentJar :agent-jdk25:compileFpReport

output=/state/build/agent-jdk25
jar="$output/libs/ohmyrasp-agent.jar"
java -cp "$jar:$output/classes/fpReport" FpReport --check >/tmp/fp-report.md
grep -F '| **Overall**' /tmp/fp-report.md
if (( $# )); then
  probe=$1
  shift
  if [[ "$probe" == file-delete ]]; then
    python3 scripts/fp-harness/check-file-read.py "$jar" --delete-only "$@"
  else
    python3 "scripts/fp-harness/check-$probe.py" "$jar" "$@"
  fi
  echo "JDK 25 packaged check passed: $probe"
fi
CONTAINER
