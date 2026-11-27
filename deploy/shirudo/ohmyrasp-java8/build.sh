#!/bin/sh
# Build the OhMyRASP Java 8 shirudo upatch jar and optional .bee package:
#   deploy/shirudo/ohmyrasp-java8/build.sh [--jar-only] [--mode block|monitor] <version> [bpm build options...]

set -eu

track=java8
pkg_name="ohmyrasp-${track}"
jar_name="${pkg_name}.jar"
gradle_task=":agent-${track}:shirudoUpatchJar"

jar_only=0
mode=block

usage() {
	echo "usage: $0 [--jar-only] [--mode block|monitor] <version> [bpm build options...]" >&2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--jar-only)
		jar_only=1
		shift
		;;
	--mode)
		[ $# -ge 2 ] || { usage; exit 2; }
		mode=$2
		shift 2
		;;
	--mode=*)
		mode=${1#--mode=}
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	--)
		shift
		break
		;;
	-*)
		echo "unknown option: $1" >&2
		usage
		exit 2
		;;
	*)
		break
		;;
	esac
done

case "$mode" in
block|monitor) ;;
*)
	echo "invalid --mode '$mode': expected block or monitor" >&2
	exit 2
	;;
esac

if [ "$jar_only" -eq 0 ]; then
	[ $# -ge 1 ] || { usage; exit 2; }
	version=$1
	shift
fi

pkg=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$pkg/../../.." && pwd)
java_agent_dir="$repo_root/java-agent"
start=$PWD

if command -v gradle >/dev/null 2>&1; then
	(
		cd "$java_agent_dir"
		OHMYRASP_SHIRUDO_MODE="$mode" gradle --no-daemon \
			"$gradle_task" \
			"-PshirudoMode=$mode" \
			"-Pohmyrasp.shirudo.mode=$mode" \
			"-Pohmyrasp.mode=$mode"
	)
else
	# The image is the one java-agent/Dockerfile pins, resolved the way CI does; the build runs as the caller.
	gradle_image=$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { print $2; exit }' "$java_agent_dir/Dockerfile")
	[ -n "$gradle_image" ] || { echo "no 'FROM gradle:...' line in $java_agent_dir/Dockerfile" >&2; exit 1; }
	gradle_home=${OHMYRASP_GRADLE_HOME:-$HOME/.cache/ohmyrasp-gradle-home}
	mkdir -p "$gradle_home"
	docker run --rm \
		-u "$(id -u):$(id -g)" \
		-e HOME=/tmp/gradle-home \
		-e GRADLE_USER_HOME=/gradle-home \
		-e "OHMYRASP_SHIRUDO_MODE=$mode" \
		-v "$gradle_home:/gradle-home" \
		-v "$java_agent_dir:/workspace" \
		-w /workspace \
		"$gradle_image" \
		gradle --no-daemon --no-problems-report --project-cache-dir /tmp/gradle-proj-pkg \
		"$gradle_task" \
		"-PshirudoMode=$mode" \
		"-Pohmyrasp.shirudo.mode=$mode" \
		"-Pohmyrasp.mode=$mode"
fi

src_jar="$java_agent_dir/agent-${track}/build/libs/$jar_name"
[ -f "$src_jar" ] || { echo "missing built jar: $src_jar" >&2; exit 1; }
cp "$src_jar" "$pkg/$jar_name"

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec "${SHIRUDO_BIN:-shirudo}" bpm build "$pkg" --version "$version" "$@"
