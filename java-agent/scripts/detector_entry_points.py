"""Public detect* entry points of the primary agent's detector classes.

gen-detection-coverage.py and deploy/shirudo/gen-readmes.py both report these,
so the rule that finds them lives here once. An entry point is a public method
named detect<Name>, or plain detect in a <Name>Detector class, declared at class level in a source file of
agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/. Hooks call the class
that owns each one.

Two kinds of public detect* method are not capabilities of the agent, and by_class() and capabilities() leave
them out. One serves only rule ids the catalogue marks not wired (rules/general.json, "not_wired"): no hook
module reaches it; not_wired_by_class() lists it. The other is a compatibility stub whose every overload is
`return Optional.empty();` (detectHessianType, detectProtocolClassInstantiation, detectJaasConfig): it decides
nothing, and the rule it is named for is decided by another entry point; stubs_by_class() lists it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rule_wiring  # noqa: E402

DETECT = (Path(__file__).resolve().parent.parent
          / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent" / "detect")
_ENTRY = re.compile(r"^  public (?:static )?[^\n(]+\bdetect([A-Z][A-Za-z0-9]+)?\(", re.M)


def _entry_points() -> dict[str, dict[str, str]]:
    """{class: {capability name: method name}} for each detect-package class with a public detect* method."""
    owners: dict[str, dict[str, str]] = {}
    for src in sorted(DETECT.glob("*.java")):
        # A method named plain `detect` is the capability its class is named for (RemoteJobDetector.detect).
        found = {name or src.stem.removesuffix("Detector"): f"detect{name}"
                 for name in _ENTRY.findall(src.read_text(encoding="utf-8"))}
        if found:
            owners[src.stem] = dict(sorted(found.items()))
    return owners


def _stub(owner: str, method: str) -> bool:
    return (owner, method) in rule_wiring.empty_stubs()


def by_class() -> dict[str, list[str]]:
    """{class: sorted capability names}, for each detect-package class with a public detect* method that decides something
    and that a hook can reach."""
    owners: dict[str, list[str]] = {}
    for owner, found in _entry_points().items():
        names = [name for name, method in found.items()
                 if not rule_wiring.serves_only_not_wired(owner, method) and not _stub(owner, method)]
        if names:
            owners[owner] = names
    return owners


def stubs_by_class() -> dict[str, list[str]]:
    """{class: sorted capability names} of the public detect* methods that only return an empty result."""
    owners: dict[str, list[str]] = {}
    for owner, found in _entry_points().items():
        names = [name for name, method in found.items() if _stub(owner, method)]
        if names:
            owners[owner] = names
    return owners


def not_wired_by_class() -> dict[str, list[str]]:
    """{class: sorted capability names} of the public detect* methods that serve only not wired rule ids."""
    owners: dict[str, list[str]] = {}
    for owner, found in _entry_points().items():
        names = [name for name, method in found.items() if rule_wiring.serves_only_not_wired(owner, method) and not _stub(owner, method)]
        if names:
            owners[owner] = names
    return owners


def capabilities() -> list[str]:
    """Distinct capability names (the <Name> of detect<Name>) across the detect package, hook-reachable ones only."""
    return sorted({name for names in by_class().values() for name in names})
