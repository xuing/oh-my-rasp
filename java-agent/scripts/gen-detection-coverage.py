#!/usr/bin/env python3
"""Generate docs/DETECTION-COVERAGE.md from the agent sources and test suite.

This is the single source of truth for "what OhMyRASP can detect". It is
derived, not written by hand, so it stays correct as hooks, detectors, and
acceptance scenarios are added. Re-run it after changing any of:

  * agent/src/main/java/io/ohmyrasp/agent/asm/HookRegistry.java   (hook families)
  * agent/src/main/java/io/ohmyrasp/agent/detect/DetectorEngine.java (capabilities)
  * scripts/acceptance-vulhub-*.sh                                (verified scenarios)

Usage:  python3 scripts/gen-detection-coverage.py [--check]
        --check exits non-zero if the committed doc is stale (for CI).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent"
SCRIPTS = ROOT / "scripts"
OUT = ROOT / "docs" / "DETECTION-COVERAGE.md"

JDK_ORDER = ["java7-legacy", "java8", "java11", "java17", "java21"]


def hook_families() -> list[str]:
    """Default hook modules registered by HookRegistry.defaults()."""
    text = (AGENT / "asm" / "HookRegistry.java").read_text(encoding="utf-8")
    names = re.findall(r"new ([A-Za-z0-9]+HookModule)\(", text)
    return sorted(set(names))


def detector_capabilities() -> list[str]:
    """Distinct detect* methods exposed by DetectorEngine."""
    text = (AGENT / "detect" / "DetectorEngine.java").read_text(encoding="utf-8")
    names = re.findall(r"\bdetect([A-Z][A-Za-z0-9]+)\(", text)
    return sorted(set(names))


def verified_algorithms() -> list[str]:
    """Algorithm signatures asserted by the acceptance suite (verified coverage)."""
    algos: set[str] = set()
    for script in SCRIPTS.glob("acceptance*.sh"):
        text = script.read_text(encoding="utf-8", errors="ignore")
        algos.update(re.findall(r'"algorithm":"([a-z0-9_]+)"', text))
    return sorted(algos)


def vulnerability_matrix() -> list[tuple[str, str]]:
    """(target, jdk) for each end-to-end vulhub acceptance scenario."""
    rows: list[tuple[str, str]] = []
    for script in sorted(SCRIPTS.glob("acceptance-vulhub-*.sh")):
        stem = script.stem[len("acceptance-vulhub-"):]
        jdk = next((j for j in JDK_ORDER if stem.endswith("-" + j)), None)
        if jdk is None:
            # Fall back to the trailing javeNN token.
            m = re.search(r"-(java[0-9a-z\-]+)$", stem)
            jdk = m.group(1) if m else "unknown"
            target = stem[: -(len(jdk) + 1)] if m else stem
        else:
            target = stem[: -(len(jdk) + 1)]
        rows.append((target, jdk))
    return rows


def group_algorithms(algos: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = {}
    for algo in algos:
        m = re.match(r"(java[0-9]+)_", algo)
        key = m.group(1) if m else "common"
        groups.setdefault(key, []).append(algo)
    return groups


def render() -> str:
    families = hook_families()
    capabilities = detector_capabilities()
    algos = verified_algorithms()
    matrix = vulnerability_matrix()

    by_jdk: dict[str, list[str]] = {}
    by_app: dict[str, int] = {}
    for target, jdk in matrix:
        by_jdk.setdefault(jdk, []).append(target)
        app = target.split("-")[0]
        by_app[app] = by_app.get(app, 0) + 1

    lines: list[str] = []
    w = lines.append
    w("# OhMyRASP Detection Coverage")
    w("")
    w("> **Generated** by `scripts/gen-detection-coverage.py` — derived from the agent")
    w("> sources and acceptance suite, not written by hand. Re-run after changing hooks,")
    w("> detectors, or acceptance scripts. `--check` fails CI when this file is stale.")
    w("")
    w("## Summary")
    w("")
    w(f"| Metric | Count |")
    w(f"|--------|------:|")
    w(f"| Hook families (instrumentation points) | {len(families)} |")
    w(f"| Detector capabilities (engine entry points) | {len(capabilities)} |")
    w(f"| Verified algorithm signatures (asserted by tests) | {len(algos)} |")
    w(f"| End-to-end vulnerability acceptance scenarios | {len(matrix)} |")
    w(f"| JDK lines exercised | {len([j for j in by_jdk if j != 'unknown'])} |")
    w("")

    w("## Hook families")
    w("")
    w("Instrumentation points registered by `HookRegistry.defaults()`. Each module")
    w("rewrites a family of risky call sites and routes them to the detector engine.")
    w("")
    w("| Family | Hook module |")
    w("|--------|-------------|")
    for module in families:
        family = module[: -len("HookModule")]
        w(f"| {family} | `{module}` |")
    w("")

    w("## Detector capabilities")
    w("")
    w(f"The engine exposes **{len(capabilities)}** detection entry points:")
    w("")
    # Three-column flow for compactness.
    pretty = [f"`detect{c}`" for c in capabilities]
    for i in range(0, len(pretty), 3):
        w("- " + " · ".join(pretty[i:i + 3]))
    w("")

    w("## Verified algorithm signatures")
    w("")
    w("Algorithm identifiers asserted by the acceptance suite — i.e. detections that")
    w("are proven end-to-end, not merely implemented.")
    w("")
    for key in sorted(group_algorithms(algos)):
        members = group_algorithms(algos)[key]
        w(f"**{key}** ({len(members)})")
        w("")
        for algo in members:
            w(f"- `{algo}`")
        w("")

    w("## Tested vulnerability matrix")
    w("")
    w("End-to-end acceptance scenarios that run a real vulnerable application under")
    w("the agent and assert the expected detection/block. Counts by JDK line:")
    w("")
    w("| JDK | Scenarios |")
    w("|-----|----------:|")
    for jdk in JDK_ORDER + [j for j in sorted(by_jdk) if j not in JDK_ORDER]:
        if jdk in by_jdk:
            w(f"| {jdk} | {len(by_jdk[jdk])} |")
    w(f"| **total** | **{len(matrix)}** |")
    w("")
    w("Top application families by scenario count:")
    w("")
    w("| Application | Scenarios |")
    w("|-------------|----------:|")
    for app, count in sorted(by_app.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        w(f"| {app} | {count} |")
    w("")
    w("<details><summary>Full scenario list</summary>")
    w("")
    for jdk in JDK_ORDER + [j for j in sorted(by_jdk) if j not in JDK_ORDER]:
        if jdk not in by_jdk:
            continue
        w(f"### {jdk} ({len(by_jdk[jdk])})")
        w("")
        for target in sorted(by_jdk[jdk]):
            w(f"- {target}")
        w("")
    w("</details>")
    w("")
    return "\n".join(lines) + "\n"


def main() -> int:
    content = render()
    if "--check" in sys.argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != content:
            print("DETECTION-COVERAGE.md is stale; run scripts/gen-detection-coverage.py", file=sys.stderr)
            return 1
        print("DETECTION-COVERAGE.md is up to date.")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
