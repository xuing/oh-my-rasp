#!/usr/bin/env bash

prepare_ysoserial_jar() {
  local target_jar="${1:-${OHMYRASP_YSOSERIAL_JAR:-${OHMYRASP_YSOSERIAL_DIR:-/tmp/ohmyrasp-ysoserial}/ysoserial.jar}}"
  local maven_image="${OHMYRASP_MAVEN_JDK8_IMAGE:-maven:3.8.1-jdk-8}"
  local target_dir
  local uid
  local gid

  if [[ -s "$target_jar" ]]; then
    return 0
  fi

  target_dir="$(dirname "$target_jar")"
  mkdir -p "$target_dir"

  # Previous interrupted Docker builds can leave root-owned partial trees in
  # /tmp/ohmyrasp-ysoserial. Remove only this dedicated cache before rebuilding.
  docker run --rm -v "${target_dir}:/work" -w /work "$maven_image" \
    bash -lc 'rm -rf src ysoserial.jar' >/dev/null

  uid="$(id -u)"
  gid="$(id -g)"
  docker run --rm \
    --user "${uid}:${gid}" \
    -e HOME=/tmp \
    -e MAVEN_CONFIG=/tmp/.m2 \
    -v "${target_dir}:/work" \
    -w /work \
    "$maven_image" \
    bash -lc 'git clone --depth 1 https://github.com/frohoff/ysoserial.git src && cd src && mvn -q -DskipTests package && cp target/ysoserial-*-all.jar /work/ysoserial.jar'

  if [[ ! -s "$target_jar" ]]; then
    echo "ysoserial jar was not built at ${target_jar}" >&2
    return 1
  fi
}
