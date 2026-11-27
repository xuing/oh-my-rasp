#!/usr/bin/env python3
"""Generate java-agent/docs/HOOK-TARGETS.md, and the hook-miss report's tables, from the recorded hook maps.

The maps are java-agent/probes/hook-targets/recorded/{primary,backport}.txt, written by the
hook-targets probe from the packaged agents over real library JARs; libraries.toml says which
versions. The tables are META-INF/ohmyrasp/hook-expectations/{primary,backport}.txt of the :shared
module, which every agent JAR carries: the library classes each hook unit is expected to instrument,
less what probes/hook-targets/hook-miss.toml exempts. This reads only those files, so it needs no
Docker and no network.

Usage:  python3 java-agent/scripts/gen-hook-targets.py [--check]
        --check exits non-zero if the document or a table is stale (for CI).
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
    w("the hook stops applying silently. The `hook-targets` probe runs each packaged agent over")
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
    w("## What the map does not show")
    w("")
    w("The transformers run on class files with no class loader that resolves anything and with")
    w("`classBeingRedefined` unset, so that the result does not depend on the checker's classpath. Two paths")
    w("of the running agent are therefore absent from the map and no recorded row speaks for them:")
    w("")
    w("- The JDBC hook that recognises an already-loaded statement implementation which inherits a JDBC")
    w("  interface keys on the loaded class, not on its bytes. A driver class matched only that way is not")
    w("  listed here.")
    w("- Behaviour that depends on a loader other than a plain application loader, such as an OSGi framework")
    w("  loader.")
    w("")
    w("Entries under `META-INF/versions/` are scanned for multi-release JARs (`Multi-Release: true`) and")
    w("recorded with that prefix; a JAR that is not multi-release does not load them, so they are skipped.")
    w("")
    w("A backport transformer counts only when its entry class constructs it and passes it to")
    w("`Instrumentation.addTransformer`, and the backport map is the chained run in registration order, as")
    w("production runs it. A class on which a transformer adds something else after its predecessors than on the")
    w("original bytes is a `# chain:` line in the recorded map and is listed below.")
    w("")
    w("## At run time")
    w("")
    w("Each agent JAR carries a table derived from these maps: per hook unit, the classes it hooks on some")
    w("recorded version and the methods it hooks there. A running agent writes one diagnostic line when it")
    w("loads such a class and the unit hooks none of those methods, so a version the probe never saw is")
    w("reported where it runs ([docs/agent.md](../../docs/agent.md#hooks-that-did-not-apply)). The probe")
    w("runs the agent with that report on over the libraries below and fails on a version that the unit does")
    w("not hook unless [`hook-miss.toml`](../probes/hook-targets/hook-miss.toml) explains it:")
    w("")
    w("| Unit | Class | Check | Why |")
    w("|---|---|---|---|")
    for pair in sorted(hookmap.load_hook_miss().values(), key=lambda p: (p.unit, p.cls)):
        w(f"| `{pair.unit}` | `{pair.cls}` | {pair.check} | {pair.why} |")
    w("")
    w("`absent`: not reported when the class declares no method of a name the unit looks for (a release from")
    w("before the hooked code existed). `never`: not reported.")
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
    w("## Chained transformers")
    w("")
    chain = maps["backport"].chain
    if chain:
        w("Backport transformers that add something different after the transformers before them than on the")
        w("original class. Each is a hook that the order of registration changes.")
        w("")
        for line in chain:
            w(f"- `{line}`")
    else:
        w("None: every backport transformer adds the same rows after its predecessors as on the original class.")
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


def outputs() -> dict[Path, str]:
    """Every file this script writes, with its content."""
    maps = hookmap.load_recorded()
    hook_miss = hookmap.load_hook_miss()
    problems = hookmap.hook_miss_entry_problems(maps, hook_miss)
    if problems:
        raise SystemExit("gen-hook-targets: " + "; ".join(problems))
    files = {OUTPUT: render()}
    for family, hook_map in maps.items():
        files[hookmap.EXPECTATIONS / f"{family}.txt"] = hookmap.expectation_table(family, hook_map, hook_miss)
    return files


def main() -> int:
    files = outputs()
    stale = [path for path, content in files.items()
             if not path.exists() or path.read_text(encoding="utf-8") != content]
    if "--check" in sys.argv:
        if stale:
            names = ", ".join(str(path.relative_to(REPO)) for path in stale)
            print(f"gen-hook-targets: stale — {names}. Run"
                  " `python3 java-agent/scripts/gen-hook-targets.py` and commit the result.", file=sys.stderr)
            return 1
        print("gen-hook-targets: HOOK-TARGETS.md and the hook-miss tables are up to date.")
        return 0
    for path in stale:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(files[path], encoding="utf-8")
        print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
