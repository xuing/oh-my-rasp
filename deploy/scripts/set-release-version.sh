#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: deploy/scripts/set-release-version.sh VERSION [IMAGE_NAMESPACE] [REGISTRY]

Updates Helm chart metadata and default image references for a release.

Arguments:
  VERSION          Docker-tag-safe semantic version, for example 0.1.0 or 0.1.0-rc.1.
  IMAGE_NAMESPACE Image namespace under the registry. Defaults to ohmyrasp.
  REGISTRY        Image registry hostname. Defaults to ghcr.io.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

version="${1:-}"
image_namespace="${2:-ohmyrasp}"
registry="${3:-ghcr.io}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -z "$version" ]]; then
  usage >&2
  exit 2
fi

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
  echo "error: VERSION must be a Docker-tag-safe semantic version without build metadata" >&2
  exit 2
fi

if [[ ! "$image_namespace" =~ ^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*$ ]]; then
  echo "error: IMAGE_NAMESPACE must be lowercase Docker path components" >&2
  exit 2
fi

if [[ ! "$registry" =~ ^[a-z0-9][a-z0-9.-]*(:[0-9]+)?$ ]]; then
  echo "error: REGISTRY must be a lowercase registry hostname, optionally with a port" >&2
  exit 2
fi

export OHMYRASP_RELEASE_VERSION="$version"
export OHMYRASP_RELEASE_NAMESPACE="$image_namespace"
export OHMYRASP_RELEASE_REGISTRY="$registry"
export OHMYRASP_REPO_ROOT="$repo_root"

python3 <<'PY'
from pathlib import Path
import os
import re

repo_root = Path(os.environ["OHMYRASP_REPO_ROOT"])
chart_path = repo_root / "deploy" / "helm" / "ohmyrasp-control" / "Chart.yaml"
values_path = repo_root / "deploy" / "helm" / "ohmyrasp-control" / "values.yaml"

version = os.environ["OHMYRASP_RELEASE_VERSION"]
namespace = os.environ["OHMYRASP_RELEASE_NAMESPACE"]
registry = os.environ["OHMYRASP_RELEASE_REGISTRY"]

chart = chart_path.read_text(encoding="utf-8")
chart, version_count = re.subn(r"(?m)^version: .+$", f"version: {version}", chart, count=1)
chart, app_version_count = re.subn(r'(?m)^appVersion: .+$', f'appVersion: "{version}"', chart, count=1)
if version_count != 1 or app_version_count != 1:
    raise SystemExit("missing expected Chart.yaml version or appVersion key")
chart_path.write_text(chart, encoding="utf-8")

api_repository = f"{registry}/{namespace}/control-api"
web_repository = f"{registry}/{namespace}/control-web"

lines = values_path.read_text(encoding="utf-8").splitlines()
section = None
image_block = False
repository_updated = {"api": False, "web": False}
tag_updated = {"api": False, "web": False}
out = []

for line in lines:
    if re.match(r"^[A-Za-z][A-Za-z0-9_-]*:", line):
        section = line.split(":", 1)[0]
        image_block = False

    if section in {"api", "web"} and re.match(r"^  image:\s*$", line):
        image_block = True
        out.append(line)
        continue

    if image_block and section == "api" and re.match(r"^    repository:\s*", line):
        out.append(f"    repository: {api_repository}")
        repository_updated["api"] = True
        continue

    if image_block and section == "web" and re.match(r"^    repository:\s*", line):
        out.append(f"    repository: {web_repository}")
        repository_updated["web"] = True
        continue

    if image_block and section in {"api", "web"} and re.match(r"^    tag:\s*", line):
        out.append(f"    tag: {version}")
        tag_updated[section] = True
        continue

    if image_block and line and not line.startswith("    "):
        image_block = False

    out.append(line)

missing = [
    f"{section}.{field}"
    for section in ("api", "web")
    for field, updated in (
        ("image.repository", repository_updated[section]),
        ("image.tag", tag_updated[section]),
    )
    if not updated
]
if missing:
    raise SystemExit(f"missing expected values.yaml keys: {', '.join(missing)}")

values_path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY

echo "Updated ohmyrasp-control chart and image tags to ${version}"
