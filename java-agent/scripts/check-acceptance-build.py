#!/usr/bin/env python3
"""Fail when an acceptance script builds the agent without the shared helper.

Every script under java-agent/acceptance/ builds through acceptance/lib/agent-build.sh
(ohmyrasp_build), so Gradle runs in the image pinned by java-agent/Dockerfile, as the
caller's uid, and OHMYRASP_AGENT_JAR can replace the build. This check flags:

  - a `docker` command that runs `gradle` or `gradlew`, with or without a path
    (`/opt/gradle/bin/gradle`, `./gradlew`);
  - a Gradle build run on the host: `gradle`, `./gradlew` or `path/to/gradlew` in command
    position;
  - a literal `gradle:<tag>` image (use "$(ohmyrasp_gradle_image)" when a script only
    needs a JDK container);
  - a script that calls an ohmyrasp_* helper function without sourcing exactly
    acceptance/lib/agent-build.sh (a `source` of `agent-build.sh.bak` or of another
    directory's `agent-build.sh` does not count, and is flagged).

  - a variable set or defaulted to someone's home directory or to a dated Vulhub snapshot under /tmp: a file
    from the Vulhub checkout is found through "${OHMYRASP_VULHUB_ROOT:?...}", which a
    per-script variable may still override.

A comment, whole-line or at the end of a line, is not scanned. Other libraries
(acceptance/lib/ysoserial.sh) may be sourced.

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
DOCKER = re.compile(r"\bdocker\b")
# A Gradle executable in command position: at the start of a statement (after any VAR=value
# assignments) or after ; & | ( ` $( , with or without a path, `gradle` or `gradlew`.
HOST_GRADLE = re.compile(
    r"(?:^|[;&|(`]|\$\()\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:\S*/)?gradlew?(?:\.bat)?(?=\s|$|[;&|)`])"
)
# A value that only works on one machine: a variable set or defaulted to a home directory, or the
# dated Vulhub snapshot. A path inside a container (`docker exec ... /home/app/...`) is not one.
MACHINE_PATH = re.compile(r"(?::-|=\"?)/(?:home|Users)/[\w.-]+/|/tmp/vulhub-[\w.-]*")
SOURCE_STATEMENT = re.compile(r"^\s*(?:source|\.)\s+(\S+)")
# Exactly the helper: `acceptance/lib/agent-build.sh`, optionally after one variable
# (`"${agent_root}/acceptance/lib/agent-build.sh"`), optionally quoted.
SOURCES_HELPER = re.compile(
    r'^\s*(?:source|\.)\s+"?(?:\$\{\w+\}/|\$\w+/)?acceptance/lib/agent-build\.sh"?\s*(?:;|&&)?\s*$'
)


def strip_inline_comment(line: str) -> str:
    """The line up to a `#` that starts a comment: outside quotes, at the start of a word."""
    quote = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and quote == '"':
                i += 1
            elif ch == quote:
                quote = ""
        elif ch == "\\":
            i += 1
        elif ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i]
        i += 1
    return line


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
        kept = [strip_inline_comment(p.rstrip("\\")) for p in parts if not p.lstrip().startswith("#")]
        yield first, " ".join(kept)
        i += 1


def without_single_quoted(statement: str) -> str:
    """The statement with the text of each single-quoted string removed: nothing in it runs."""
    return re.sub(r"'[^']*'", "''", statement)


def runs_gradle_in_docker(statement: str) -> bool:
    for token in statement.split():
        token = token.strip("\"'")
        if token.startswith("-") or "=" in token or ":" in token:
            continue
        if token.rsplit("/", 1)[-1] in ("gradle", "gradlew"):
            return True
    return False


def violations(text: str) -> list[tuple[int, str]]:
    found = []
    sources_helper = False
    uses_helper = False
    for number, statement in statements(text):
        if not statement.strip():
            continue
        if any(name in statement for name in HELPER_FUNCTIONS):
            uses_helper = True
        source = SOURCE_STATEMENT.match(statement)
        if source and "agent-build" in source.group(1):
            if SOURCES_HELPER.match(statement):
                sources_helper = True
            else:
                found.append((number, "sources " + source.group(1) + ", not exactly " + HELPER))
        if MACHINE_PATH.search(statement):
            found.append((number, "names a path that exists on one machine; a Vulhub file is "
                                  '"${OHMYRASP_VULHUB_ROOT:?set OHMYRASP_VULHUB_ROOT to a Vulhub checkout}/<path>"'))
        if GRADLE_IMAGE.search(statement):
            found.append((number, 'names a gradle: image; use "$(ohmyrasp_gradle_image)" from ' + HELPER))
        elif DOCKER.search(statement):
            if GRADLE_COMMAND.search(statement) or runs_gradle_in_docker(statement):
                found.append((number, "runs Gradle in Docker; call ohmyrasp_build from " + HELPER))
        elif HOST_GRADLE.search(without_single_quoted(statement)):
            found.append((number, "runs Gradle on the host; call ohmyrasp_build from " + HELPER))
    if uses_helper and not sources_helper:
        found.append((1, "calls an ohmyrasp_* helper function without sourcing exactly " + HELPER))
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
