#!/bin/sh
# Build the universal OhMyRASP shirudo upatch jar (every Java line, 8 to 25) and optional .bee package:
#   deploy/shirudo/ohmyrasp/build.sh [--jar-only] [--mode block|monitor] <version> [bpm build options...]

set -eu

pkg=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
pkg_name=${pkg##*/}
jar_name="${pkg_name}.jar"
gradle_task=":agent-all:shirudoUpatchJar"

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

src_jar="$java_agent_dir/agent-all/build/libs/$jar_name"
[ -f "$src_jar" ] || { echo "missing built jar: $src_jar" >&2; exit 1; }
cp "$src_jar" "$pkg/$jar_name"

# The `fixes` list of the Beefile says which advisories the loaded agent blocks, which only a block build does.
# A block build is packaged from this directory. A monitor build is packaged from a staged copy whose Beefile
# has no `fixes` line (deploy/shirudo/stage/monitor/ohmyrasp, ignored by git), and verify-shirudo-upatch.sh
# checks that the baked mode and the Beefile it is packaged with agree.
stage_parent=$(CDPATH= cd -- "$pkg/.." && pwd)/stage/monitor
rm -rf "$stage_parent"
build_dir=$pkg
if [ "$mode" = monitor ]; then
	build_dir=$stage_parent/$pkg_name
	mkdir -p "$build_dir"
	sed '/^[[:space:]]*fixes[[:space:]]*=/d' "$pkg/Beefile" > "$build_dir/Beefile"
	cp "$pkg/README.md" "$pkg/$jar_name" "$build_dir/"
	echo "$pkg_name: a monitor build lists no fixes in its Beefile ($build_dir/Beefile); fixes describes the block build only."
fi

[ "$jar_only" -eq 0 ] || exit 0
cd "$start"
exec "${SHIRUDO_BIN:-shirudo}" bpm build "$build_dir" --version "$version" "$@"
