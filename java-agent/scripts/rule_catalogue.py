"""Rule ids, and what it means for a script to assert one.

The catalogue (rules/general.json and rules/product.json) describes every primary rule id and every
backport rule family. A backport line emits a family as `<line>_<family>` (java8_file_script_write),
except for the few families its hooks emit unprefixed. Those are read from the hooks, so the set of
ids is exactly what the agents can log.

A primary id the agent can never report, because nothing the packaged agent runs reaches the code that
would, is listed under "not_wired" beside "primary" and "backports", with the reason, in the file where its
description lives. Counts of what the agent detects leave those ids out. test_rule_cases.py (WiringTest)
checks the list against the sources, in both directions.

A script asserts an id when the id appears in it as a whole token: not as part of a longer word, a
file name, a path or a `key:value` pair.
gen-detection-coverage.py builds its acceptance lists with this definition and scripts/check-docs.py
checks the ledger claims with it.
"""
from __future__ import annotations

import functools
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # java-agent/
RULES = ROOT / "rules"
BACKPORT_LINES = ("java8", "java11", "java17")
# A word that stands alone: not part of a dotted name, a path, a hyphenated slug or a `key:value` pair
# (java8.sh loops over `jmx_file_write:/rasp/java8/jmx-file-write` routes and writes `jmx_file_write.response`).
TOKEN = re.compile(r"(?<![\w./-])\w+(?![\w/-]|[.:][\w/])")


def _catalogue(section: str) -> set[str]:
    return {key for name in ("general.json", "product.json")
            for key in json.loads((RULES / name).read_text(encoding="utf-8"))[section]}


def not_wired() -> dict[str, str]:
    """Primary rule id -> why no hook can report it. An id is described in one file and marked in the same one."""
    found: dict[str, str] = {}
    for name in ("general.json", "product.json"):
        data = json.loads((RULES / name).read_text(encoding="utf-8"))
        for rule, reason in data.get("not_wired", {}).items():
            if rule not in data["primary"]:
                raise ValueError(f"{name}: not_wired names {rule}, which is not one of its primary ids")
            if not reason.strip():
                raise ValueError(f"{name}: not_wired {rule} needs a reason")
            found[rule] = reason
    return found


def wired_primary_ids() -> set[str]:
    """Primary ids a hook can report: the catalogue's primary ids less the not wired ones."""
    return primary_ids() - not_wired().keys()


def with_not_wired(uncovered: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    """rules/cases/uncovered.toml's lists plus the not wired primary ids, each with the catalogue's reason.

    The reason of a not wired id has one home, the catalogue; listing the id in uncovered.toml too is an error.
    """
    merged = {engine: dict(ids) for engine, ids in uncovered.items()}
    for rule, reason in not_wired().items():
        if rule in merged["primary"]:
            raise ValueError(f"uncovered.toml lists {rule}, which the catalogue marks not wired: "
                             "take it off uncovered.toml, its reason is in rules/general.json")
        merged["primary"][rule] = f"not wired: {reason.rstrip('.')}"
    return merged


def primary_ids() -> set[str]:
    return _catalogue("primary")


def backport_families() -> set[str]:
    return _catalogue("backports")


def backport_findings() -> dict[str, list[str]]:
    """Backport line -> the rule ids its hooks emit as `new Finding("<id>"`, in source order."""
    found: dict[str, list[str]] = {}
    for line in BACKPORT_LINES:
        hooks = ROOT / f"agent-{line}" / "src/main/java/io/ohmyrasp/agent" / line / f"{line.capitalize()}RaspHooks.java"
        names = re.findall(r'new Finding\(\s*"(\w+)"', hooks.read_text(encoding="utf-8"))
        found[line] = list(dict.fromkeys(names))
    return found


@functools.cache
def rule_ids() -> frozenset[str]:
    """Every id an agent can log: primary ids, and each backport family with its line prefix or as emitted."""
    families = backport_families()
    prefixed = {f"{line}_{family}" for line in BACKPORT_LINES for family in families}
    return frozenset(primary_ids() | prefixed | {n for names in backport_findings().values() for n in names})


@functools.cache
def catalogue_ids() -> frozenset[str]:
    """Every id the catalogue describes: primary ids, and each backport family bare or with a line prefix.

    scripts/check-docs.py treats a backticked word on a ledger row as a claim exactly when it is one of these.
    """
    families = backport_families()
    return frozenset(primary_ids() | families | {f"{line}_{f}" for line in BACKPORT_LINES for f in families})


def tokens(text: str) -> set[str]:
    return set(TOKEN.findall(text))


def asserted(text: str) -> set[str]:
    """The rule ids that appear in a script as whole tokens."""
    return tokens(text) & rule_ids()
