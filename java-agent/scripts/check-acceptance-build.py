#!/usr/bin/env python3
"""Fail when an acceptance script builds the agent without the shared helper.

Every script under java-agent/acceptance/ builds through acceptance/lib/agent-build.sh
(ohmyrasp_build), so Gradle runs in the image pinned by java-agent/Dockerfile, as the
caller's uid, and OHMYRASP_AGENT_JAR can replace the build. This check flags:

  - a `docker` command that runs `gradle` or `gradlew`;
  - a literal `gradle:<tag>` image (use "$(ohmyrasp_gradle_image)" when a script only
    needs a JDK container);
  - a script that calls an ohmyrasp_* helper function without sourcing agent-build.sh.

Run: python3 java-agent/scripts/check-acceptance-build.py
"""
import re
import sys
from pathlib import Path

ACCEPTANCE = Path(__file__).resolve().parent.parent / "acceptance"
HELPER = "acceptance/lib/agent-build.sh"
HELPER_FUNCTIONS = ("ohmyrasp_build", "ohmyrasp_agent_jar", "ohmyrasp_gradle_image")

GRADLE_IMAGE = re.compile(r"\bgradle:[\w][\w.-]*")
GRADLE_COMMAND = re.compile(r"(?<![\w:./-])gradlew?(?![\w:./-])")
SOURCES_HELPER = re.compile(r"^\s*(?:source|\.)\s+\S*acceptance/lib/agent-build\.sh", re.M)


def statements(text: str):
    """(first line number, text) of each shell statement: continuation lines joined, comments dropped."""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        parts = [lines[i]]
        while parts[-1].rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            parts.append(lines[i])
        first = i + 1 - (len(parts) - 1)
        yield first, " ".join(p.rstrip("\\") for p in parts if not p.lstrip().startswith("#"))
        i += 1


def violations(text: str) -> list[tuple[int, str]]:
    found = []
    for number, statement in statements(text):
        if statement.lstrip().startswith("#"):
            continue
        if GRADLE_IMAGE.search(statement):
            found.append((number, 'names a gradle: image; use "$(ohmyrasp_gradle_image)" from ' + HELPER))
        elif re.search(r"\bdocker\b", statement) and GRADLE_COMMAND.search(statement):
            found.append((number, "runs Gradle in Docker; call ohmyrasp_build from " + HELPER))
    uses_helper = any(name in text for name in HELPER_FUNCTIONS)
    if uses_helper and not SOURCES_HELPER.search(text):
        found.append((1, "calls an ohmyrasp_* helper function without sourcing " + HELPER))
    return found


def scripts(root: Path = ACCEPTANCE) -> list[Path]:
    return sorted(p for p in root.glob("**/*.sh") if p.relative_to(root).as_posix() != "lib/agent-build.sh")


def main() -> int:
    failures = 0
    checked = scripts()
    for path in checked:
        for number, why in violations(path.read_text()):
            print(f"{path.relative_to(ACCEPTANCE.parent.parent)}:{number}: {why}", file=sys.stderr)
            failures += 1
    if failures:
        print(f"{failures} acceptance build problem(s)", file=sys.stderr)
        return 1
    print(f"acceptance build check passed: {len(checked)} scripts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
