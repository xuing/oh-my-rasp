#!/usr/bin/env bash
# Regenerate docs/FALSE-POSITIVE-REPORT.md by running the FP harness against the
# real DetectorEngine inside the JDK 25 build image. Requires Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/docs/FALSE-POSITIVE-REPORT.md"
IMAGE="${GRADLE_IMAGE:-gradle:jdk25}"

cd "$ROOT"
docker run --rm -v "$ROOT":/workspace -w /workspace "$IMAGE" bash -c '
  set -e
  gradle --no-daemon -g /tmp/gh --project-cache-dir /tmp/pc :agent-jdk25:agentJar >/dev/null 2>&1
  mkdir -p /tmp/fp
  javac -cp agent-jdk25/build/libs/ohmyrasp-agent.jar -d /tmp/fp scripts/fp-harness/FpReport.java
  java -cp "agent-jdk25/build/libs/ohmyrasp-agent.jar:/tmp/fp" FpReport 2>/dev/null
' > "$OUT"

echo "wrote $OUT"
