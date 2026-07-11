#!/usr/bin/env bash
#
# check-detector-parity.sh
#
# Guards against false-positive-suppression drift between the flat single-file
# RASP hook implementations (agent-java8 is the source of truth; agent-java11 and
# agent-java17 are its byte-identical siblings) and, where applicable, the
# agent-jdk25 DetectorEngine.
#
# It asserts, purely via grep, that the three benign-path carve-outs added in
# commit 8920474 are present in every module that must carry them:
#
#   1. isMavenRepositoryArtifactWrite   (benign ~/.m2/repository/*.jar writes)
#   2. isBenignInternalServicePath      (benign Nacos internal maintenance path)
#   3. isKnownLiferayPortalInclude      (benign Liferay portal .jsp includes)
#
# Fails (non-zero exit) if any expected symbol is missing, so CI blocks the drift.

set -euo pipefail

# Resolve the java-agent root regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

fail=0

require_symbol() {
  local file="$1"
  local symbol="$2"
  if [[ ! -f "$file" ]]; then
    echo "PARITY FAIL: file not found: $file" >&2
    fail=1
    return
  fi
  if ! grep -q "$symbol" "$file"; then
    echo "PARITY FAIL: missing '$symbol' in $file" >&2
    fail=1
  fi
}

# ---------------------------------------------------------------------------
# Flat single-file variants: java8 (source of truth) + java11 + java17.
# Each must contain BOTH the guard call site AND the helper definitions.
# ---------------------------------------------------------------------------
for variant in java8 java11 java17; do
  Variant="$(tr '[:lower:]' '[:upper:]' <<<"${variant:0:1}")${variant:1}"
  hooks="$ROOT/agent-$variant/src/main/java/io/ohmyrasp/agent/$variant/${Variant}RaspHooks.java"

  # Symbol 1: Maven .m2 artifact write carve-out.
  require_symbol "$hooks" "isMavenRepositoryArtifactWrite"
  # Symbol 2: Nacos internal maintenance-path carve-out.
  require_symbol "$hooks" "isBenignInternalServicePath"
  # Symbol 3: Liferay portal internal-include carve-out (+ its companion helper).
  require_symbol "$hooks" "isKnownLiferayPortalInclude"
  require_symbol "$hooks" "isKnownLiferayInternalIncludePath"
done

# ---------------------------------------------------------------------------
# agent-jdk25 uses a different architecture (detect/DetectorEngine.java) and a
# different symbol set:
#
#   * Nacos    -> isBenignInternalServicePath   (same name; guards looksLikeInternalIdentityBypass)
#   * Liferay  -> isKnownLiferayPortalInclude   (same name; guards detectServletIncludeAttributes)
#   * Maven    -> INTENTIONALLY EXCLUDED. jdk25's SCRIPT_FILE pattern does NOT
#                 include jar/war/ear/class, so a benign ~/.m2/repository/*.jar
#                 write is never classified as a script write and never blocked.
#                 The FP is eliminated by construction, so no carve-out symbol
#                 exists (or is needed) in jdk25. Do not add one here.
# ---------------------------------------------------------------------------
jdk25_engine="$ROOT/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/DetectorEngine.java"
require_symbol "$jdk25_engine" "isBenignInternalServicePath"
require_symbol "$jdk25_engine" "isKnownLiferayPortalInclude"
require_symbol "$jdk25_engine" "isKnownLiferayInternalIncludePath"

if [[ "$fail" -ne 0 ]]; then
  echo "" >&2
  echo "Detector false-positive-suppression parity check FAILED." >&2
  echo "agent-java8 is the source of truth; port missing carve-outs to the modules above." >&2
  exit 1
fi

echo "Detector false-positive-suppression parity check passed (java8/java11/java17 + jdk25)."
