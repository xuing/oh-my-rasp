#!/bin/sh
# Build all OhMyRASP shirudo Java upatch packages:
#   deploy/shirudo/build-all.sh [--jar-only] [--mode block|monitor] <version> [bpm build options...]

set -eu

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

root=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

for pkg in ohmyrasp-java8 ohmyrasp-java11 ohmyrasp-java17 ohmyrasp-jdk21 ohmyrasp-jdk25; do
	echo "==> building $pkg (mode=$mode, jar_only=$jar_only)"
	if [ "$jar_only" -eq 1 ]; then
		"$root/$pkg/build.sh" --jar-only --mode "$mode"
	else
		"$root/$pkg/build.sh" --mode "$mode" "$version" "$@"
	fi
done
