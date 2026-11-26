#!/usr/bin/env python3
"""Generate java-agent/docs/HOOK-TARGETS.md from the recorded hook maps.

The maps are java-agent/probes/hook-targets/recorded/{primary,backport}.txt, written by the
hook-targets probe from the packaged agents over real library JARs; libraries.toml says which
versions. This reads only those files, so it needs no Docker and no network.

Usage:  python3 java-agent/scripts/gen-hook-targets.py [--check]
        --check exits non-zero if the document is stale (for CI).
"""
from __future__ import annotations

import collections
import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PROBE = REPO / "java-agent" / "probes" / "hook-targets"
OUTPUT = REPO / "java-agent" / "docs" / "HOOK-TARGETS.md"
SHOWN_PER_GAP = 4

spec = importlib.util.spec_from_file_location("hookmap", PROBE / "hookmap.py")
hookmap = importlib.util.module_from_spec(spec)
sys.modules["hookmap"] = hookmap
spec.loader.exec_module(hookmap)


def hooked_methods(hook_map) -> dict:
    """(library, version) -> set of (class, method, descriptor) hooked on a named target."""
    found: dict = collections.defaultdict(set)
    for row in hookmap.named_rows(hook_map):
        found[(row.library, row.version)].add((row.cls, row.method, row.descriptor))
    return found


def gaps(libraries, hook_map) -> list[tuple[str, str, str, list[str]]]:
    """Per library, a method hooked in some versions and not in the others, grouped by those versions.

    The unit is class and method name; descriptors that differ between versions count as one method.
    """
    by_method: dict = collections.defaultdict(set)
    for row in hookmap.named_rows(hook_map):
        by_method[(row.library, row.cls, row.method)].add(row.version)
    grouped: dict = collections.defaultdict(list)
    for (library, cls, method), versions in sorted(by_method.items()):
        every = next(lib for lib in libraries if lib.id == library).versions
        missing = tuple(v for v in every if v not in versions)
        if missing:
            grouped[(library, tuple(v for v in every if v in versions), missing)].append(f"{cls}.{method}")
    return [(library, " ".join(hooked), " ".join(missing), sorted(methods))
            for (library, hooked, missing), methods in sorted(grouped.items())]


def render() -> str:
    libraries = hookmap.load_libraries()
    maps = hookmap.load_recorded()
    counts = {family: hooked_methods(hook_map) for family, hook_map in maps.items()}
    out = []
    w = out.append
    w("# Hook Targets in Third-Party Libraries")
    w("")
    w("> **Generated** by `scripts/gen-hook-targets.py` from `probes/hook-targets/recorded/` and")
    w("> `probes/hook-targets/libraries.toml`, not written by hand. Regenerate it after the")
    w("> `hook-targets` probe records a new map; `--check` fails CI when this file is stale.")
    w("")
    w("A hook aimed at a library matches a class name and a method. When a release renames the method,")
    w("the hook stops applying and nothing says so. The `hook-targets` probe runs each packaged agent over")
    w("every class of real library JARs and records which methods come out calling back into the agent.")
    w("This page summarises those recorded maps; the full rows are in")
    w("[`recorded/primary.txt`](../probes/hook-targets/recorded/primary.txt) and")
    w("[`recorded/backport.txt`](../probes/hook-targets/recorded/backport.txt), the versions and why they")
    w("were chosen in [`libraries.toml`](../probes/hook-targets/libraries.toml).")
    w("")
    w("A hooked method is one class, method and descriptor that an agent rewrites to call into itself. The")
    w("call-site rewriting that the primary agent applies to any class (JDBC and multipart call sites) is")
    w("not counted, only hooks on named targets. Primary is the JDK 21 and 25 agent, backport the Java 8,")
    w("11 and 17 agents, which record the same map.")
    w("")
    w("## Hooked methods per library version")
    w("")
    w("| Library | Version | Primary | Backport |")
    w("|---|---|--:|--:|")
    for library in libraries:
        for version in library.versions:
            key = (library.id, version)
            cells = [str(len(counts[family].get(key, ()))) for family in hookmap.FAMILIES]
            note = " (no hook, see below)" if version in library.none else ""
            w(f"| `{library.id}` | {version}{note} | {cells[0]} | {cells[1]} |")
    w("")
    w("## Versions with no hook")
    w("")
    none = [(lib, version, reason) for lib in libraries for version, reason in lib.none.items()]
    if none:
        w("Each is listed under `none` in `libraries.toml` with its reason. A reason starting with FINDING")
        w("is a hook that should be fixed.")
        w("")
        w("| Library | Version | Reason |")
        w("|---|---|---|")
        for lib, version, reason in none:
            w(f"| `{lib.id}` | {version} | {reason} |")
    else:
        w("None: every version has at least one hooked method.")
    w("")
    w("## Hook families with no library target")
    w("")
    allowlist = hookmap.load_allowlist()
    w("Hook families that rewrite no method of any listed library, from")
    w("[`allowlist.toml`](../probes/hook-targets/allowlist.toml). The probe fails when one stops being needed.")
    for family in hookmap.FAMILIES:
        w("")
        w(f"**{family.capitalize()}**")
        w("")
        w("| Hook family | Why |")
        w("|---|---|")
        for unit, reason in allowlist[family].items():
            w(f"| `{unit}` | {reason} |")
    w("")
    w("## Version gaps")
    w("")
    w("A method (class and method name) that an agent hooks in some versions of a library and not in")
    w("others. Most are renames between major versions (`javax` to `jakarta`, a moved package, a new")
    w("signature); each is a place to check that the hook still covers what it did.")
    for family in hookmap.FAMILIES:
        w("")
        w(f"### {family.capitalize()}")
        w("")
        found = gaps(libraries, maps[family])
        if not found:
            w("None.")
            continue
        w("| Library | Hooked in | Not hooked in | Methods |")
        w("|---|---|---|---|")
        for library, hooked, missing, methods in found:
            shown = "<br>".join(f"`{m}`" for m in methods[:SHOWN_PER_GAP])
            more = f"<br>and {len(methods) - SHOWN_PER_GAP} more" if len(methods) > SHOWN_PER_GAP else ""
            w(f"| `{library}` | {hooked} | {missing} | {shown}{more} |")
    w("")
    return "\n".join(out)


def main() -> int:
    content = render()
    if "--check" in sys.argv:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != content:
            print("gen-hook-targets: stale — java-agent/docs/HOOK-TARGETS.md. Run"
                  " `python3 java-agent/scripts/gen-hook-targets.py` and commit the result.", file=sys.stderr)
            return 1
        print("gen-hook-targets: HOOK-TARGETS.md is up to date.")
        return 0
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != content:
        OUTPUT.write_text(content, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
