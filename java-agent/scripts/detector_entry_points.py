"""Public detect* entry points of the primary agent's detector classes.

gen-detection-coverage.py and deploy/shirudo/gen-readmes.py both report these,
so the rule that finds them lives here once. An entry point is a public method
named detect<Name>, or plain detect in a <Name>Detector class, declared at class level in a source file of
agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/. Hooks call the class
that owns each one.
"""
from __future__ import annotations

import re
from pathlib import Path

DETECT = (Path(__file__).resolve().parent.parent
          / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent" / "detect")
_ENTRY = re.compile(r"^  public (?:static )?[^\n(]+\bdetect([A-Z][A-Za-z0-9]+)?\(", re.M)


def by_class() -> dict[str, list[str]]:
    """{class: sorted capability names}, for each detect-package class with a public detect* method."""
    owners: dict[str, list[str]] = {}
    for src in sorted(DETECT.glob("*.java")):
        # A method named plain `detect` is the capability its class is named for (RemoteJobDetector.detect).
        names = sorted({name or src.stem.removesuffix("Detector")
                        for name in _ENTRY.findall(src.read_text(encoding="utf-8"))})
        if names:
            owners[src.stem] = names
    return owners


def capabilities() -> list[str]:
    """Distinct capability names (the <Name> of detect<Name>) across the detect package."""
    return sorted({name for names in by_class().values() for name in names})
