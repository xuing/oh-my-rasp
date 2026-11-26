#!/usr/bin/env bash
# Replay the Vulhub acceptance script of every advisory in deploy/shirudo/fixes.toml against the universal
# agent JAR, and print one result line per advisory.
#
#   OHMYRASP_VULHUB_ROOT=<vulhub checkout> deploy/shirudo/replay-fixes.sh [--only <ID>]... [--jar <path>]
#
# This is a manual step, not CI: the scripts start the `vulhub/*` images (they need Docker and network to
# pull them) and some read a Vulhub checkout. The scripts' wording shows what they assert; only this run shows
# that the universal JAR passes them. After a run that changes agent code, set `replayed` (and `replayed_with`)
# of each entry in fixes.toml to the date and JAR of this run, then run gen-readmes.py.
#
# The JAR is built through java-agent/acceptance/lib/agent-build.sh (the Gradle image java-agent/Dockerfile
# pins, run as the caller; OHMYRASP_GRADLE_HOME and OHMYRASP_SKIP_AGENT_BUILD apply) and handed to each
# script through OHMYRASP_AGENT_JAR, which the acceptance scripts honour in place of their own per-line JAR.
# Logs go to java-agent/logs/replay-fixes/ (override with OHMYRASP_REPLAY_LOGS).
#
# Exit status: 0 when every selected advisory passes, 1 when one fails, 2 for a usage or setup error.

set -uo pipefail

usage() {
	echo "usage: OHMYRASP_VULHUB_ROOT=<vulhub checkout> $0 [--only <ID>]... [--jar <path>]" >&2
}

only=()
jar=""
while [ $# -gt 0 ]; do
	case "$1" in
	--only)
		[ $# -ge 2 ] || { usage; exit 2; }
		only+=("$2")
		shift 2
		;;
	--jar)
		[ $# -ge 2 ] || { usage; exit 2; }
		jar=$2
		shift 2
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

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
shirudo_dir="$root/deploy/shirudo"
agent_dir="$root/java-agent"
logs=${OHMYRASP_REPLAY_LOGS:-$agent_dir/logs/replay-fixes}

pairs=$(python3 -I "$shirudo_dir/fixes_check.py" --scripts) || { echo "cannot read fixes.toml" >&2; exit 2; }
if [ "${#only[@]}" -gt 0 ]; then
	selected=""
	for id in "${only[@]}"; do
		line=$(printf '%s\n' "$pairs" | awk -F'\t' -v id="$id" '$1 == id')
		[ -n "$line" ] || { echo "$id is not in fixes.toml" >&2; exit 2; }
		selected="$selected$line"$'\n'
	done
	pairs=${selected%$'\n'}
fi
[ -n "$pairs" ] || { echo "fixes.toml lists no advisory" >&2; exit 2; }

# Scripts that read a Vulhub checkout say so; fail before any container starts when it is not given.
if [ -z "${OHMYRASP_VULHUB_ROOT:-}" ]; then
	needs=$(printf '%s\n' "$pairs" | while IFS=$'\t' read -r id script; do
		grep -q OHMYRASP_VULHUB_ROOT "$agent_dir/$script" && echo "  $id  $script"
	done)
	if [ -n "$needs" ]; then
		echo "OHMYRASP_VULHUB_ROOT is not set; set it to a Vulhub checkout. These scripts need it:" >&2
		printf '%s\n' "$needs" >&2
		exit 2
	fi
elif [ ! -d "$OHMYRASP_VULHUB_ROOT" ]; then
	echo "OHMYRASP_VULHUB_ROOT is not a directory: $OHMYRASP_VULHUB_ROOT" >&2
	exit 2
fi

if [ -z "$jar" ]; then
	# shellcheck source=/dev/null
	source "$agent_dir/acceptance/lib/agent-build.sh"
	mkdir -p "$logs"
	echo "building ohmyrasp-agent-all.jar (log: $logs/build.log)"
	ohmyrasp_build :agent-all:agentAllJar >"$logs/build.log" 2>&1 \
		|| { tail -n 20 "$logs/build.log" >&2; echo "building ohmyrasp-agent-all.jar failed" >&2; exit 2; }
	jar="$agent_dir/agent-all/build/libs/ohmyrasp-agent-all.jar"
fi
case "$jar" in /*) ;; *) jar="$PWD/$jar" ;; esac
[ -f "$jar" ] || { echo "no such JAR: $jar" >&2; exit 2; }
jar_sha=$(sha256sum "$jar" | cut -d' ' -f1)

mkdir -p "$logs"
echo "replaying against $(basename "$jar") (sha256 $jar_sha)"

failed=0
total=0
for id in $(printf '%s\n' "$pairs" | cut -f1 | awk '!seen[$0]++'); do
	total=$((total + 1))
	status=PASS
	detail=""
	started=$SECONDS
	for script in $(printf '%s\n' "$pairs" | awk -F'\t' -v id="$id" '$1 == id { print $2 }'); do
		log="$logs/$id-$(basename "$script" .sh).log"
		if OHMYRASP_AGENT_JAR="$jar" bash "$agent_dir/$script" >"$log" 2>&1; then
			detail="$detail $script"
		else
			status=FAIL
			detail="$detail $script (log: $log; last line: $(tail -n 1 "$log" | cut -c1-160))"
		fi
	done
	[ "$status" = PASS ] || failed=$((failed + 1))
	printf '%s %s (%ss)%s\n' "$status" "$id" "$((SECONDS - started))" "$detail"
done

echo "$((total - failed)) of $total advisories passed against $(basename "$jar") on $(date +%F) (sha256 $jar_sha)"
if [ "$failed" -eq 0 ] && [ "${#only[@]}" -eq 0 ]; then
	echo "all passed: set replayed = \"$(date -u +%F)\" (a UTC date) and replayed_with = \"$(basename "$jar")\" on every entry in deploy/shirudo/fixes.toml, then run gen-readmes.py"
fi
[ "$failed" -eq 0 ]
