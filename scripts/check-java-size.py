#!/usr/bin/env python3
"""Enforce the physical line limit for Java source files in this checkout."""
import os
from pathlib import Path
import subprocess


MAX_LINES = 5000
ROOT = Path(__file__).resolve().parents[1]


def main():
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.java"], cwd=ROOT
    )
    failed = False
    for name in names.split(b"\0"):
        if not name:
            continue
        path = ROOT / os.fsdecode(name)
        if path.is_file():
            count = len(path.read_bytes().splitlines())
            if count > MAX_LINES:
                print(f"{path.relative_to(ROOT)}: {count} lines (limit {MAX_LINES})")
                failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
