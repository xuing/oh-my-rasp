#!/usr/bin/env python3
"""Fail when the three backport lines drift apart without a record.

agent-java8, agent-java11 and agent-java17 are three source trees on purpose: each may use the
syntax of its own Java release. They must still decide the same things. This tool compares the
java11 and java17 trees with the java8 tree after replacing the version token, and keeps every
remaining difference in a reviewed file:

    scripts/backport-drift.java11.diff
    scripts/backport-drift.java17.diff

A change made in one line only shows up as a difference that is not in those files, and the check
fails. Then either make the same change in the other lines, or, when the difference is meant
(newer syntax, a per-release constant), record it:

    python3 java-agent/scripts/check-backport-drift.py --update

and say why in the commit. The recorded files are the list of places where a line uses its own
syntax, so read their diff in review.

Compared: `build.gradle.kts` and everything under `src/main` of each line. A line's own `src/test`
is not compared: tests that all three lines share live in `backport-tests/`.
"""
from __future__ import annotations

import argparse
import difflib
import re
import sys
from pathlib import Path

BASE = "8"
SIBLINGS = ("11", "17")
COMPARED = ("build.gradle.kts", "src/main")

# Version tokens, most specific first. `(?!\d)` keeps "java8" from matching inside "java80".
TOKENS = (
    (re.compile(r"Opcodes\.V(?:1_8|11|17)(?!\d)"), "Opcodes.V<N>"),
    (re.compile(r"((?:java|Java|JAVA)[ _-]?)(?:8|11|17)(?!\d)"), r"\1<N>"),
)

HEADER = """\
# Differences between agent-java{base} and agent-java{line}, after replacing the version token with <N>.
# Written by java-agent/scripts/check-backport-drift.py --update. Do not edit by hand.
# "-" lines are agent-java{base}, "+" lines are agent-java{line}. A file with no entry is the same in both.
"""


def normalise(text: str) -> str:
    for pattern, replacement in TOKENS:
        text = pattern.sub(replacement, text)
    return text


def line_files(root: Path, line: str) -> dict[str, Path]:
    """Compared files of one line, keyed by their path with the version token replaced."""
    module = root / f"agent-java{line}"
    found: dict[str, Path] = {}
    for entry in COMPARED:
        start = module / entry
        paths = [start] if start.is_file() else sorted(p for p in start.rglob("*") if p.is_file())
        for path in paths:
            found[normalise(path.relative_to(module).as_posix())] = path
    return found


def hunks(base: list[str], other: list[str]) -> list[str]:
    out: list[str] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, base, other, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        out.append("@@")
        out.extend("-" + text for text in base[i1:i2])
        out.extend("+" + text for text in other[j1:j2])
    return out


def read_lines(path: Path) -> list[str] | None:
    try:
        return normalise(path.read_text(encoding="utf-8")).splitlines()
    except UnicodeDecodeError:
        return None


def drift(root: Path, line: str) -> str:
    """The text recorded for one sibling line."""
    base_files = line_files(root, BASE)
    other_files = line_files(root, line)
    out = [HEADER.format(base=BASE, line=line)]
    for key in sorted(set(base_files) | set(other_files)):
        if key not in other_files:
            out.append(f"== {key}\nonly in agent-java{BASE}\n")
            continue
        if key not in base_files:
            out.append(f"== {key}\nonly in agent-java{line}\n")
            continue
        base, other = read_lines(base_files[key]), read_lines(other_files[key])
        if base is None or other is None:
            if base_files[key].read_bytes() != other_files[key].read_bytes():
                out.append(f"== {key}\nbinary files differ\n")
            continue
        found = hunks(base, other)
        if found:
            out.append(f"== {key}\n" + "\n".join(found) + "\n")
    return "\n".join(out)


def recorded_path(root: Path, line: str) -> Path:
    return root / "scripts" / f"backport-drift.java{line}.diff"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail when the three backport lines drift apart without a record.")
    parser.add_argument("--update", action="store_true", help="rewrite the recorded differences")
    parser.add_argument("--check", action="store_true", help="compare with the recorded differences (default)")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                        help="the java-agent directory")
    args = parser.parse_args(argv)

    failed = False
    for line in SIBLINGS:
        current = drift(args.root, line)
        path = recorded_path(args.root, line)
        if args.update:
            path.write_text(current, encoding="utf-8")
            print(f"wrote {path.relative_to(args.root.parent)}")
            continue
        recorded = path.read_text(encoding="utf-8") if path.is_file() else ""
        if recorded == current:
            continue
        failed = True
        name = path.relative_to(args.root.parent).as_posix()
        print(f"agent-java{BASE} and agent-java{line} differ in a way {name} does not record:\n", file=sys.stderr)
        sys.stderr.writelines(difflib.unified_diff(
            recorded.splitlines(keepends=True), current.splitlines(keepends=True),
            "recorded", "now", n=2))
        print(file=sys.stderr)
    if failed:
        print("A backport change reaches all three lines: make the same change in each of agent-java8,\n"
              "agent-java11 and agent-java17. If the difference is meant (newer syntax, a per-release\n"
              "constant), record it with `python3 java-agent/scripts/check-backport-drift.py --update`\n"
              "and say why in the commit.", file=sys.stderr)
        return 1
    if not args.update:
        print(f"backport lines: no unrecorded difference (java{BASE} against " +
              ", ".join(f"java{line}" for line in SIBLINGS) + ")")
    return 0


if __name__ == "__main__":
    sys.exit(main())
