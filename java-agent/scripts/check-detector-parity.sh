#!/usr/bin/env bash
#
# check-detector-parity.sh
#
# Guards against false-positive-suppression drift between the backport decisions
# (one copy for agent-java8, agent-java11 and agent-java17, in
# shared/src/main/java/io/ohmyrasp/agent/backport/BackportHooks.java) and, where
# applicable, the agent-jdk25 detect/ package.
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

# Passes when "$symbol(" is called in a .java file under "$where": on a line that is neither a comment nor
# the helper's own declaration. A definition alone, or a mention in a comment, guards nothing. The bracket
# expression lists "]" first and holds no backslash, so it means the same to every POSIX grep.
require_symbol() {
  local where="$1"
  local symbol="$2"
  if [[ ! -e "$where" ]]; then
    echo "PARITY FAIL: file not found: $where" >&2
    fail=1
    return
  fi
  if ! grep -rhE --include='*.java' "\\b${symbol}\\(" "$where" \
      | grep -vE '^[[:space:]]*(//|/?\*)' \
      | grep -vE "^[[:space:]]*((public|private|protected|static|final|synchronized)[[:space:]]+)+[][A-Za-z0-9_<>?,. ]+[[:space:]]${symbol}[[:space:]]*\\(" \
      | grep -q .; then
    echo "PARITY FAIL: no call of '$symbol' in $where (a definition or a comment is not a guard)" >&2
    fail=1
  fi
}

# ---------------------------------------------------------------------------
# The backport decisions, one copy for the three backport lines.
# Each carve-out must be called, not only defined.
# ---------------------------------------------------------------------------
hooks="$ROOT/shared/src/main/java/io/ohmyrasp/agent/backport/BackportHooks.java"

# Symbol 1: Maven .m2 artifact write carve-out.
require_symbol "$hooks" "isMavenRepositoryArtifactWrite"
# Symbol 2: Nacos internal maintenance-path carve-out.
require_symbol "$hooks" "isBenignInternalServicePath"
# Symbol 3: Liferay portal internal-include carve-out (+ its companion helper).
require_symbol "$hooks" "isKnownLiferayPortalInclude"
require_symbol "$hooks" "isKnownLiferayInternalIncludePath"

# ---------------------------------------------------------------------------
# agent-jdk25 uses a different architecture (one class per rule family in detect/) and a
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
jdk25_detectors="$ROOT/agent-jdk25/src/main/java/io/ohmyrasp/agent/detect"
require_symbol "$jdk25_detectors" "isBenignInternalServicePath"
require_symbol "$jdk25_detectors" "isKnownLiferayPortalInclude"
require_symbol "$jdk25_detectors" "isKnownLiferayInternalIncludePath"

if [[ "$fail" -ne 0 ]]; then
  echo "" >&2
  echo "Detector false-positive-suppression parity check FAILED." >&2
  echo "shared/.../backport/BackportHooks.java holds the backport decisions; port missing carve-outs to the files above." >&2
  exit 1
fi

echo "Detector false-positive-suppression parity check passed (java8/java11/java17 + jdk25)."
