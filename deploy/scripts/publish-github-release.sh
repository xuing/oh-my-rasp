#!/usr/bin/env bash
set -euo pipefail

# Publish or update an immutable GitHub Release for OhMyRASP, following
# Magpie's idempotent create/edit, --clobber upload, asset-completeness check,
# and SemVer-aware Latest reconciliation pattern.

VERSION="${VERSION:?VERSION is required}"
REF="${REF:-v${VERSION}}"
DIST_DIR="${DIST_DIR:-dist}"
EXPECTED_ASSETS="${EXPECTED_ASSETS:-15}"
IMAGE_NAMESPACE="${IMAGE_NAMESPACE:?IMAGE_NAMESPACE is required}"
REGISTRY="${REGISTRY:-ghcr.io}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
GITHUB_SHA="${GITHUB_SHA:?GITHUB_SHA is required}"
EVENT_NAME="${EVENT_NAME:-${GITHUB_EVENT_NAME:-push}}"
CHANGELOG_PATH="${CHANGELOG_PATH:-CHANGELOG.md}"

if [[ ! -d "$DIST_DIR" ]]; then
  echo "DIST_DIR does not exist: $DIST_DIR" >&2
  exit 1
fi

shopt -s nullglob
assets=("$DIST_DIR"/*)
shopt -u nullglob
if [[ "${#assets[@]}" -eq 0 ]]; then
  echo "No release assets found in $DIST_DIR" >&2
  exit 1
fi

prerelease=false
if [[ "$VERSION" == *-* ]]; then
  prerelease=true
fi

newest_stable_tag() {
  gh release list -R "$GITHUB_REPOSITORY" -L 100 --exclude-drafts --exclude-pre-releases \
    --json tagName -q '.[].tagName' |
    { grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true; } |
    sort -V |
    tail -1
}

latest=false
if [[ "$prerelease" == "false" ]]; then
  top="$(newest_stable_tag)"
  if [[ -z "$top" ]] || [[ "$(printf '%s\n%s\n' "$top" "$REF" | sort -V | tail -1)" == "$REF" ]]; then
    latest=true
  else
    echo "$top is newer than $REF: publishing without the Latest mark"
  fi
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
notes_file="$tmp_dir/release-notes.md"

extract_changelog_section() {
  local changelog="$1"
  local version="$2"
  local out="$3"
  [[ -f "$changelog" ]] || return 1
  python3 - "$changelog" "$version" "$out" <<'PY'
import re
import sys

changelog_path, version, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(changelog_path, "r", encoding="utf-8") as fh:
    lines = fh.read().splitlines()

header_re = re.compile(r"^## \[" + re.escape(version) + r"\](?:\s|$)")
next_re = re.compile(r"^## \[")
capture = False
collected = []
for line in lines:
    if not capture:
        if header_re.match(line):
            capture = True
        continue
    if next_re.match(line):
        break
    collected.append(line)

body = "\n".join(collected).strip()
if not body:
    sys.exit(1)

with open(out_path, "w", encoding="utf-8") as out:
    out.write(body + "\n")
PY
}

if ! extract_changelog_section "$CHANGELOG_PATH" "$VERSION" "$notes_file"; then
  if ! gh api "repos/${GITHUB_REPOSITORY}/releases/generate-notes" \
    -f tag_name="$REF" \
    -f target_commitish="$GITHUB_SHA" \
    -q .body > "$notes_file" 2>/dev/null || [[ ! -s "$notes_file" ]]; then
    printf 'OhMyRASP %s (%s)\n' "$REF" "${GITHUB_SHA::12}" > "$notes_file"
  fi
fi

cat >> "$notes_file" <<EOF

---

## Release Artifacts

- **Java Agents (standard)**: \`ohmyrasp-agent-java8.jar\`, \`ohmyrasp-agent-java11.jar\`, \`ohmyrasp-agent-java17.jar\`, \`ohmyrasp-agent-jdk21.jar\`, \`ohmyrasp-agent.jar\`
- **shirudo Java upatch JARs (standalone/daemonless)**: \`ohmyrasp-java8.jar\`, \`ohmyrasp-java11.jar\`, \`ohmyrasp-java17.jar\`, \`ohmyrasp-jdk21.jar\`, \`ohmyrasp-jdk25.jar\`
- **JDK 21 Shirudo package ready to sign**: \`ohmyrasp-jdk21-shirudo.tar.gz\`
- **shirudo Beefile bundle**: \`ohmyrasp-shirudo-upatches-${VERSION}.tar.gz\`
- **Rust Host Daemon**: \`ohmyrasp-daemon-linux-amd64.tar.gz\`
- **Control Plane Images & Helm Chart**:
  - \`${REGISTRY}/${IMAGE_NAMESPACE}/control-api:${VERSION}\`
  - \`${REGISTRY}/${IMAGE_NAMESPACE}/control-web:${VERSION}\`
  - \`oci://${REGISTRY}/${IMAGE_NAMESPACE}/charts/ohmyrasp-control:${VERSION}\`

## Verification

\`\`\`bash
sha256sum -c SHA256SUMS.txt
gh attestation verify ohmyrasp-shirudo-upatches-${VERSION}.tar.gz -R ${GITHUB_REPOSITORY}
gh attestation verify ohmyrasp-control-${VERSION}.tgz -R ${GITHUB_REPOSITORY}
\`\`\`
EOF

if gh release view "$REF" -R "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  gh release edit "$REF" -R "$GITHUB_REPOSITORY" \
    --title "OhMyRASP $REF" \
    --notes-file "$notes_file" \
    --prerelease="$prerelease" \
    --latest="$latest"
  gh release upload "$REF" "${assets[@]}" -R "$GITHUB_REPOSITORY" --clobber
else
  create_flags=(
    --title "OhMyRASP $REF"
    --notes-file "$notes_file"
    --prerelease="$prerelease"
    --latest="$latest"
  )
  if [[ "$EVENT_NAME" == "push" ]] || gh api "repos/${GITHUB_REPOSITORY}/git/ref/tags/${REF}" >/dev/null 2>&1; then
    create_flags+=(--verify-tag)
  else
    create_flags+=(--target "$GITHUB_SHA")
  fi
  gh release create "$REF" "${assets[@]}" -R "$GITHUB_REPOSITORY" "${create_flags[@]}"
fi

asset_count="$(gh release view "$REF" -R "$GITHUB_REPOSITORY" --json assets -q '.assets | length')"
echo "$REF has $asset_count assets (expected >= $EXPECTED_ASSETS)"
if [[ "$asset_count" -lt "$EXPECTED_ASSETS" ]]; then
  echo "Release $REF is missing assets ($asset_count < $EXPECTED_ASSETS)" >&2
  exit 1
fi

if [[ "$prerelease" == "false" ]]; then
  top="$(newest_stable_tag)"
  current_latest="$(gh api "repos/${GITHUB_REPOSITORY}/releases/latest" -q .tag_name 2>/dev/null || true)"
  if [[ -n "$top" && "$current_latest" != "$top" ]]; then
    echo "Latest was ${current_latest:-none}: restoring Latest mark to $top"
    gh release edit "$top" -R "$GITHUB_REPOSITORY" --latest >/dev/null
  fi
fi
