#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
  cat <<'USAGE'
Usage: deploy/scripts/scan-release-images.sh IMAGE [IMAGE...]

Runs a pinned Trivy container image scan against release images. By default the
script fails when fixable critical or high vulnerabilities are detected.

Environment:
  OHMYRASP_TRIVY_IMAGE           Scanner image. Defaults to the pinned image in deploy/docker-compose.tools.yml.
  OHMYRASP_TRIVY_SEVERITIES      Comma-separated severities. Defaults to HIGH,CRITICAL.
  OHMYRASP_TRIVY_IGNORE_UNFIXED  Set to false to fail on unfixed CVEs too. Defaults to true.
  OHMYRASP_TRIVY_TIMEOUT         Trivy scan timeout. Defaults to 10m.
  TRIVY_CACHE_DIR                Optional host cache directory for Trivy DB/cache.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$#" -eq 0 ]]; then
  usage >&2
  exit 2
fi

if ! docker version >/dev/null 2>&1; then
  echo "error: Docker is not available in this environment" >&2
  exit 127
fi

trivy_image="${OHMYRASP_TRIVY_IMAGE:-$("${repo_root}/deploy/scripts/resolve-tool-image.sh" trivy)}"
severities="${OHMYRASP_TRIVY_SEVERITIES:-HIGH,CRITICAL}"
ignore_unfixed="${OHMYRASP_TRIVY_IGNORE_UNFIXED:-true}"
timeout="${OHMYRASP_TRIVY_TIMEOUT:-10m}"

if [[ ! "$trivy_image" =~ @sha256:[a-f0-9]{64}$ ]]; then
  echo "error: OHMYRASP_TRIVY_IMAGE must include an immutable sha256 digest" >&2
  exit 2
fi

cleanup_cache=false
if [[ -z "${TRIVY_CACHE_DIR:-}" ]]; then
  TRIVY_CACHE_DIR="$(mktemp -d)"
  cleanup_cache=true
fi
trap 'if [[ "$cleanup_cache" == "true" ]]; then rm -rf "$TRIVY_CACHE_DIR"; fi' EXIT

mkdir -p "$TRIVY_CACHE_DIR"

docker_config="${DOCKER_CONFIG:-$HOME/.docker}"
docker_args=(
  run
  --rm
  --user "$(id -u):$(id -g)"
  -e TRIVY_CACHE_DIR=/tmp/trivy-cache
  -e TRIVY_NO_PROGRESS=true
  -v "$TRIVY_CACHE_DIR":/tmp/trivy-cache
)

if [[ -d "$docker_config" ]]; then
  docker_args+=(-e DOCKER_CONFIG=/tmp/docker-config -v "$docker_config":/tmp/docker-config:ro)
fi

scan_args=(
  image
  --scanners vuln
  --exit-code 1
  --severity "$severities"
  --timeout "$timeout"
)

if [[ "$ignore_unfixed" == "true" ]]; then
  scan_args+=(--ignore-unfixed)
elif [[ "$ignore_unfixed" != "false" ]]; then
  echo "error: OHMYRASP_TRIVY_IGNORE_UNFIXED must be true or false" >&2
  exit 2
fi

for image in "$@"; do
  echo "Scanning ${image} for ${severities} CVEs with ${trivy_image}"
  docker "${docker_args[@]}" "$trivy_image" "${scan_args[@]}" "$image"
done
