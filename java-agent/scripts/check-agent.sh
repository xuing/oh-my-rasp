#!/usr/bin/env bash
# Incremental check of one or more agent lines against the current checkout:
# the line's unit tests, the benign corpus (primary lines), the dynamic-call
# check (backport lines), then packaged probes on the line's own JDK. Lines and
# probes come from java-agent/probes/.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
registry="$root/probes/run.py"

usage() {
  cat <<USAGE
Usage: $0 [--line LINE[,LINE...]] [--tests GRADLE-TEST-FILTER] [--artifact line|all] [PROBE|all [probe options]]

  --line      agent lines to check (default jdk25); see java-agent/probes/lines.toml
  --tests     limit each line's unit tests, for example '*RaspHooksTest'
  --artifact  probe each line's own JAR (line, the default) or the universal JAR on the
              line's JDK (all); see probes/run.py
  PROBE    one packaged probe, or "all" for every probe that applies to the line.
           Probes run on the line's own JDK. Without one, only the unit tests and
           the benign corpus run, and those run on the build JDK for every line.
           Options after PROBE go to the probe. A probe that records its result
           (--update) writes under \$PROBE_UPDATE_ROOT, and this script copies what
           it wrote into java-agent/ only when the whole run succeeds.

Probes:
USAGE
  python3 "$registry" list | sed 's/^/  /'
}

lines=jdk25
tests=""
artifact=line
while [[ "${1:-}" == -* ]]; do
  case "$1" in
    --line) lines=${2:?--line needs a value}; shift 2 ;;
    --tests) tests=${2:?--tests needs a value}; shift 2 ;;
    --artifact) artifact=${2:?--artifact needs a value}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
probe=${1:-}
if (( $# )); then shift; fi
selection=()
if [[ -n "$probe" && "$probe" != all ]]; then selection=("$probe"); fi
# Fail on an unknown line or probe before any container starts.
IFS=, read -r -a line_ids <<<"$lines"
for line in "${line_ids[@]}"; do
  python3 "$registry" plan --line "$line" --artifact "$artifact" "${selection[@]}" >/dev/null
done

gradle_image=$(awk '$1 == "FROM" && $2 ~ /^gradle:/ {print $2; exit}' "$root/Dockerfile")
image=ohmyrasp/probes:$(cat "$root/probes/Dockerfile" <(printf '%s' "$gradle_image") | sha256sum | cut -c1-12)
docker build -q --build-arg "GRADLE_IMAGE=$gradle_image" -t "$image" "$root/probes" >/dev/null

uid=$(id -u)
runtime_dir=${XDG_RUNTIME_DIR:-/run/user/$uid}
if [[ -d "$runtime_dir" && -O "$runtime_dir" && -w "$runtime_dir" ]]; then
  cache_base="$runtime_dir/ohmyrasp-agent-check"
else
  cache_base="${XDG_CACHE_HOME:-$HOME/.cache}/ohmyrasp-agent-check"
fi
checkout=$(printf '%s' "$root" | sha256sum | cut -c1-16)
state="${RASP_AGENT_CACHE:-$cache_base}/$checkout"
umask 077
mkdir -p "$state"
state=$(cd "$state" && pwd -P)
echo "Agent build cache: $state"
cache_relative=""
if [[ "$state" == "$root/"* ]]; then
  cache_relative=${state#"$root"/}
  cache_relative=${cache_relative%/*}
fi

# Keep this checkout's published jars stable while a probe is reading them.
exec 9>"$state/check.lock"
flock 9
# The checkout is read-only in the container. A probe that records its result writes it here,
# under the path it has in java-agent/, and it is copied back after a run that succeeded.
updates="$state/probe-updates"
rm -rf "$updates"
mkdir -p "$updates"
copy_probe_updates() {
  local status=$?
  [[ -n "$(ls -A "$updates")" ]] || return 0
  if (( status != 0 )); then
    # A failed run may be failing because it rejected the very result it staged (two lines of one
    # family disagreeing, a guard failing): that result must not replace the recorded baseline.
    echo "The run failed (exit $status), so nothing a probe recorded was copied into java-agent/." >&2
    echo "Staged, not copied: $updates" >&2
    (cd "$updates" && find . -type f | sed 's|^\./|  |') >&2
    return 0
  fi
  chmod -R u=rwX,go=rX "$updates"
  (umask 022; cp -R "$updates/." "$root/")
  (cd "$updates" && find . -type f | sed 's|^\./|Probe wrote java-agent/|')
}
trap copy_probe_updates EXIT
container=(docker run --rm -i --read-only --tmpfs /tmp:rw,exec -u "$uid:$(id -g)"
  -e GRADLE_USER_HOME=/state/gradle -e PYTHONDONTWRITEBYTECODE=1 -e PROBE_UPDATE_ROOT=/probe-updates
  -e "CACHE_RELATIVE=$cache_relative" -e "TEST_FILTER=$tests" -e "LINES=$lines" -e "PROBE=$probe" -e "ARTIFACT=$artifact"
  -v "$root:/workspace:ro" -v "$state:/state" -v "$updates:/probe-updates" -w /workspace)

"${container[@]}" "$image" bash -s -- "$@" <<'CONTAINER'
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

registry=(python3 probes/run.py)
selection=()
if [[ -n "$PROBE" && "$PROBE" != all ]]; then selection=("$PROBE"); fi
IFS=, read -r -a line_ids <<<"$LINES"

tasks=()
primary=false
backports=()
for line in "${line_ids[@]}"; do
  read -r family test_task < <(python3 - "$line" <<'PY'
import sys, tomllib
line = next(l for l in tomllib.load(open("probes/lines.toml", "rb"))["line"] if l["id"] == sys.argv[1])
print(line["family"], line["tests"])
PY
  )
  if [[ " ${tasks[*]} " != *" $test_task "* ]]; then
    tasks+=("$test_task")
    if [[ -n "$TEST_FILTER" ]]; then tasks+=(--tests "$TEST_FILTER"); fi
  fi
  if [[ "$family" == primary ]]; then primary=true; else backports+=("${line%-on-*}"); fi
done
build_tasks=()
# The backport JARs are always built: the dynamic-call check below reads them.
for line in "${backports[@]}"; do
  read -r -a line_tasks < <("${registry[@]}" gradle-tasks --line "$line" background-process)
  build_tasks+=("${line_tasks[@]}")
done
if [[ -n "$PROBE" ]]; then
  read -r -a probe_tasks < <("${registry[@]}" gradle-tasks --line "$LINES" --artifact "$ARTIFACT" "${selection[@]}")
  build_tasks+=("${probe_tasks[@]}")
fi
if $primary; then build_tasks+=(:agent-jdk25:agentJar :agent-jdk25:compileFpReport); fi
gradle --no-daemon --no-problems-report --configuration-cache \
  --project-cache-dir /state/project -I /tmp/build-output.gradle \
  "${tasks[@]}" "${build_tasks[@]}"

if (( ${#backports[@]} )); then
  python3 scripts/check-dynamic-calls.py --check --build-root /state/build \
    --line "$(printf '%s\n' "${backports[@]}" | sort -u | paste -sd,)"
fi
if $primary; then
  output=/state/build/agent-jdk25
  java -cp "$output/libs/ohmyrasp-agent.jar:$output/classes/fpReport" FpReport --check >/tmp/fp-report.md
  grep -F '| **Overall**' /tmp/fp-report.md
fi
if [[ -n "$PROBE" ]]; then
  "${registry[@]}" stage --build-root /state/build "${selection[@]}"
  for line in "${line_ids[@]}"; do
    jdk=$(python3 -c 'import sys, tomllib; print(next(l["jdk"] for l in tomllib.load(open("probes/lines.toml", "rb"))["line"] if l["id"] == sys.argv[1]))' "$line")
    JAVA_HOME=/opt/jdk/$jdk PATH=/opt/jdk/$jdk/bin:$PATH \
      "${registry[@]}" run --line "$line" --artifact "$ARTIFACT" --build-root /state/build --keep-going "${selection[@]}" -- "$@"
  done
fi
CONTAINER

# Probes marked isolated run again in a container without network, as CI runs them.
if [[ -n "$probe" ]]; then
  for line in "${line_ids[@]}"; do
    if ! python3 "$registry" plan --line "$line" --artifact "$artifact" --isolated "${selection[@]}" | grep -qv '^#'; then continue; fi
    jdk=$(python3 -c 'import sys, tomllib; print(next(l["jdk"] for l in tomllib.load(open(sys.argv[2], "rb"))["line"] if l["id"] == sys.argv[1]))' "$line" "$root/probes/lines.toml")
    "${container[@]}" --network none --hostname localhost \
      -e "JAVA_HOME=/opt/jdk/$jdk" -e "PATH=/opt/jdk/$jdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      "$image" python3 probes/run.py run --line "$line" --artifact "$artifact" --build-root /state/build --isolated --keep-going "${selection[@]}" -- "$@" </dev/null
  done
fi
if [[ -n "$probe" ]]; then
  echo "Agent check passed: lines=$lines, unit tests on the build JDK, probe=$probe on each line's own JDK, artifact=$artifact"
else
  echo "Agent check passed: lines=$lines, unit tests on the build JDK only. Name a probe (or all) to run the packaged JAR on each line's own JDK."
fi
