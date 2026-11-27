#!/usr/bin/env bash
# Build the agent JARs that the acceptance scripts mount into their containers.
# Source this file; do not run it:
#
#   source acceptance/lib/agent-build.sh
#   host_agent_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar")"
#   ohmyrasp_build :agent-java8:agentJava8Jar
#
# Environment:
#   OHMYRASP_AGENT_JAR=/abs/path.jar  use this JAR in place of the one the script names, and build nothing
#   OHMYRASP_SKIP_AGENT_BUILD=1       build nothing; the caller already ran Gradle
#   OHMYRASP_GRADLE_HOME=DIR          host directory used as GRADLE_USER_HOME; a relative path is
#                                     taken from the current directory
#                                     (default ~/.cache/ohmyrasp-gradle-home)

# The java-agent directory, found from this file, so any current directory works.
OHMYRASP_AGENT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)

# The Gradle image, resolved from java-agent/Dockerfile the way CI does.
ohmyrasp_gradle_image() {
  local image
  image=$(awk '$1 == "FROM" && $2 ~ /^gradle:/ { print $2; exit }' "$OHMYRASP_AGENT_DIR/Dockerfile") || image=""
  if [[ -z "$image" ]]; then
    echo "ohmyrasp: cannot resolve the Gradle image: no 'FROM gradle:...' line in $OHMYRASP_AGENT_DIR/Dockerfile" >&2
    return 1
  fi
  printf '%s\n' "$image"
}

# Print the JAR a script should mount: $OHMYRASP_AGENT_JAR when set, else the
# default path the script names. Fails when the override is not an existing file
# with an absolute path (docker would read a relative path as a volume name).
ohmyrasp_agent_jar() {
  local default=${1:?ohmyrasp_agent_jar needs a default JAR path}
  if [[ -z "${OHMYRASP_AGENT_JAR:-}" ]]; then
    printf '%s\n' "$default"
    return 0
  fi
  if [[ "$OHMYRASP_AGENT_JAR" != /* ]]; then
    echo "ohmyrasp: OHMYRASP_AGENT_JAR must be an absolute path, got: $OHMYRASP_AGENT_JAR" >&2
    return 1
  fi
  if [[ ! -f "$OHMYRASP_AGENT_JAR" ]]; then
    echo "ohmyrasp: OHMYRASP_AGENT_JAR is not a file: $OHMYRASP_AGENT_JAR" >&2
    return 1
  fi
  printf '%s\n' "$OHMYRASP_AGENT_JAR"
}

# Fail, naming the path, when an earlier root-run build left files in a build
# or .gradle directory that the caller cannot delete.
ohmyrasp_check_build_ownership() {
  local uid foreign top
  uid=$(id -u)
  foreign=$(find "$OHMYRASP_AGENT_DIR" \( -path '*/build' -o -path '*/build/*' -o -path '*/.gradle' -o -path '*/.gradle/*' \) \
    -not -user "$uid" -print -quit 2>/dev/null) || true
  if [[ -n "$foreign" ]]; then
    top=${foreign%%/build/*}
    top=${top%%/.gradle/*}
    echo "ohmyrasp: $foreign is not owned by uid $uid; an earlier build ran as root and Gradle cannot delete it." >&2
    echo "ohmyrasp: fix it with: sudo chown -R $uid:$(id -g) $top" >&2
    return 1
  fi
}

# Run Gradle tasks in the pinned image as the caller, against java-agent/.
ohmyrasp_build() {
  if (( $# == 0 )); then
    echo "ohmyrasp_build: name at least one Gradle task" >&2
    return 2
  fi
  if [[ "${OHMYRASP_SKIP_AGENT_BUILD:-}" == 1 ]]; then
    echo "ohmyrasp: OHMYRASP_SKIP_AGENT_BUILD=1, not building $*" >&2
    return 0
  fi
  if [[ -n "${OHMYRASP_AGENT_JAR:-}" ]]; then
    echo "ohmyrasp: using OHMYRASP_AGENT_JAR=$OHMYRASP_AGENT_JAR, not building $*" >&2
    return 0
  fi

  local image gradle_home
  image=$(ohmyrasp_gradle_image) || return 1
  ohmyrasp_check_build_ownership || return 1
  gradle_home=${OHMYRASP_GRADLE_HOME:-$HOME/.cache/ohmyrasp-gradle-home}
  # Docker reads a relative volume source as a volume name, so mount an absolute path. Every step
  # that can fail returns: a caller that tests this function in an `if` runs with `set -e` off,
  # and would otherwise fall through to `docker run`.
  mkdir -p -- "$gradle_home" || return 1
  gradle_home=$(cd -- "$gradle_home" && pwd -P) || return 1
  docker run --rm -u "$(id -u):$(id -g)" \
    -e HOME=/tmp/gradle-home -e GRADLE_USER_HOME=/gradle-home \
    -v "$gradle_home:/gradle-home" \
    -v "$OHMYRASP_AGENT_DIR:/workspace" -w /workspace \
    "$image" gradle --no-daemon "$@"
}
