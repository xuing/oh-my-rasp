#!/usr/bin/env python3
"""Generate docs/DETECTION-COVERAGE.md from the agent sources and test suite.

This is the single source of truth for "what OhMyRASP can detect". It is
derived, not written by hand, so it stays correct as hooks, detectors, and
acceptance scenarios are added. Re-run it after changing any of:

  * agent/src/main/java/io/ohmyrasp/agent/asm/HookRegistry.java   (hook families)
  * agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/ (public facade and rule owners)
  * scripts/acceptance-vulhub-*.sh                                (verified scenarios)

It also owns the "By the numbers" region of the root README.md and
README.zh-CN.md, between these markers (one region per file):

  <!-- BEGIN GENERATED metrics (java-agent/scripts/gen-detection-coverage.py) ... -->
  <!-- END GENERATED metrics -->

Hand-written docs must not restate these counts; link to this report instead.

Usage:  python3 scripts/gen-detection-coverage.py [--check]
        --check exits non-zero if any generated output is stale (for CI).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent"
SCRIPTS = ROOT / "scripts"
OUT = ROOT / "docs" / "DETECTION-COVERAGE.md"
REPO = ROOT.parent
FP_REPORT = ROOT / "docs" / "FALSE-POSITIVE-REPORT.md"
VULHUB_LEDGER = REPO / "docs" / "development" / "vulhub-coverage.md"
BACKPORTS = ["agent-java8", "agent-java11", "agent-java17"]
README_REGIONS = {REPO / "README.md": "en", REPO / "README.zh-CN.md": "zh"}
REGION_SLUG = "metrics"
REGION_BEGIN = (
    f"<!-- BEGIN GENERATED {REGION_SLUG} (java-agent/scripts/gen-detection-coverage.py)"
    " — do not edit between markers -->"
)
REGION_END = f"<!-- END GENERATED {REGION_SLUG} -->"

JDK_ORDER = ["java7-legacy", "java8", "java11", "java17", "java21"]


def hook_families() -> list[str]:
    """Default hook modules registered by HookRegistry.defaults()."""
    text = (AGENT / "asm" / "HookRegistry.java").read_text(encoding="utf-8")
    names = re.findall(r"new ([A-Za-z0-9]+HookModule)\(", text)
    return sorted(set(names))


def detector_capabilities() -> list[str]:
    """Distinct detect* methods exposed by DetectorEngine."""
    text = (AGENT / "detect" / "DetectorEngine.java").read_text(encoding="utf-8")
    names = re.findall(r"^  public (?:static )?[^\n(]+\bdetect([A-Z][A-Za-z0-9]+)\(", text, re.M)
    return sorted(set(names))


def asserted_algorithms() -> list[str]:
    """Algorithm IDs appearing in literal event assertions in the acceptance scripts."""
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


def backport_transformers() -> dict[str, int]:
    """Distinct ASM transformer classes instantiated by each backport track."""
    counts: dict[str, int] = {}
    for track in BACKPORTS:
        names: set[str] = set()
        for src in (ROOT / track / "src" / "main" / "java").rglob("*.java"):
            names.update(re.findall(r"new ([A-Za-z0-9]+Transformer)\(", src.read_text(encoding="utf-8")))
        counts[track] = len(names)
    return counts


def vulhub_scope() -> tuple[int, int]:
    """(roots, unique CVE tokens) declared by the Vulhub ledger's Source Audit.

    check-vulhub-java-coverage.py verifies those declarations against a Vulhub
    snapshot, so the ledger is the one home for these numbers.
    """
    audit = re.search(r"^## Source Audit\n(.*?)(?=^## |\Z)", VULHUB_LEDGER.read_text(encoding="utf-8"), re.M | re.S)
    if not audit:
        raise SystemExit(f"{VULHUB_LEDGER}: '## Source Audit' section not found")
    text = audit.group(1)
    roots = re.search(r"currently covers\s+(\d+)\s+Vulhub roots", text)
    cves = re.search(r"currently balanced:\s+(\d+)\s+unique Vulhub\s+CVE tokens", text)
    if not roots or not cves:
        raise SystemExit(f"{VULHUB_LEDGER}: Source Audit summary lines not found")
    return int(roots.group(1)), int(cves.group(1))


def fp_overall() -> tuple[int, int, int]:
    """(benign inputs, false positives, categories) from the generated FP report."""
    # The first table under "## Result": header, separator, one row per
    # category, then the **Overall** row.
    result = re.search(r"^## Result\n+((?:\|[^\n]*\n)+)", FP_REPORT.read_text(encoding="utf-8"), re.M)
    if not result:
        raise SystemExit(f"{FP_REPORT}: '## Result' table not found")
    rows = result.group(1).splitlines()[2:]
    overall = re.match(r"^\| \*\*Overall\*\* \| \*\*(\d+)\*\* \| \*\*(\d+)\*\* \|", rows[-1] if rows else "")
    if not overall:
        raise SystemExit(f"{FP_REPORT}: the Result table does not end with an **Overall** row")
    return int(overall.group(1)), int(overall.group(2)), len(rows) - 1


def rule_scope_tables() -> list[str]:
    """Index decision branches independently of the algorithms exercised by acceptance scripts."""
    rules = ROOT / "rules"
    general = json.loads((rules / "general.json").read_text(encoding="utf-8"))
    product = json.loads((rules / "product.json").read_text(encoding="utf-8"))
    sources = sorted((AGENT / "detect").rglob("*.java")) + [AGENT / "hook" / "OhMyRaspHooks.java"]
    source = "\n".join(path.read_text(encoding="utf-8") for path in sources)
    literal = set(re.findall(r'Detection\.log\(\s*(?:"[^"]+"|\w+)\s*,\s*"(\w+)"', source))
    primary = general["primary"].keys() | product["primary"].keys()
    if missing := literal - primary:
        raise ValueError(f"Primary rules missing a scope description: {sorted(missing)}")

    families: dict[str, list[str]] = {}
    for module in BACKPORTS:
        track = module.removeprefix("agent-")
        hooks = ROOT / module / "src/main/java/io/ohmyrasp/agent" / track / f"{track.capitalize()}RaspHooks.java"
        for name in sorted(set(re.findall(r'new Finding\(\s*"(\w+)"', hooks.read_text(encoding="utf-8")))):
            names = families.setdefault(name.removeprefix(track + "_"), [])
            if name not in names:
                names.append(name)
    documented = general["backports"].keys() | product["backports"].keys()
    if documented != families.keys():
        raise ValueError(f"Backport rule scope catalog differs from emitted families: {sorted(documented ^ families.keys())}")

    lines = []
    for track, title, identifiers in (
        ("primary", "Primary agent", {key: [key] for key in primary}),
        ("backports", "Backport agents", families),
    ):
        lines.extend([f"### {title}", "", "| Algorithm identifier | Cross-product evidence | Product or component dependency |", "|---|---|---|"])
        for family, names in sorted(identifiers.items()):
            ids = ", ".join(f"`{name}`" for name in names)
            lines.append(f"| {ids} | {general[track].get(family, '—')} | {product[track].get(family, '—')} |")
        lines.append("")
    return lines


def render() -> str:
    families = hook_families()
    capabilities = detector_capabilities()
    algos = asserted_algorithms()
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
    w(f"| Algorithm signatures asserted in acceptance scripts | {len(algos)} |")
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

    w("## Rule scope")
    w("")
    w("The index covers literal detection IDs in the primary engine and hooks, reviewed computed IDs, and named findings in the Java backports. A row with both columns populated has distinct branches or a product-specific exclusion. General request indicators still need runtime evidence to establish an effect.")
    w("")
    w("The descriptions live in the [general catalog](../rules/general.json) and [product-specific catalog](../rules/product.json). Scope describes applicability. Policy selection continues to use the exact event ID.")
    w("")
    lines.extend(rule_scope_tables())
    w("## Algorithm signatures asserted in acceptance scripts")
    w("")
    w("The acceptance scripts contain literal event assertions for these algorithm identifiers. Runtime evidence for individual environments is tracked in the [Vulhub coverage ledger](../../docs/development/vulhub-coverage.md).")
    w("")
    for algorithm in algos:
        w(f"- `{algorithm}`")
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


def render_metrics(lang: str) -> str:
    """The README "By the numbers" table, in English or Simplified Chinese."""
    hooks = len(hook_families())
    capabilities = len(detector_capabilities())
    algos = len(asserted_algorithms())
    scenarios = len(vulnerability_matrix())
    transformers = sorted(set(backport_transformers().values()))
    roots, cves = vulhub_scope()
    inputs, fps, categories = fp_overall()
    tracks = ", ".join(f"`{t.removeprefix('agent-')}`" for t in BACKPORTS)
    per_backport = (
        str(transformers[0]) if len(transformers) == 1 else "–".join(map(str, (transformers[0], transformers[-1])))
    )
    coverage = "[DETECTION-COVERAGE.md](java-agent/docs/DETECTION-COVERAGE.md)"
    vulhub = "[vulhub-coverage.md](docs/development/vulhub-coverage.md)"
    fp = "[FALSE-POSITIVE-REPORT.md](java-agent/docs/FALSE-POSITIVE-REPORT.md)"
    agent = "[docs/agent.md](docs/agent.md)"
    if lang == "zh":
        rows = [
            "| 维度 | 当前状态 | 依据 |",
            "|---|---|---|",
            f"| 插桩调用点家族 | {hooks} 个 ASM hook 模块（`agent-jdk25`）；回溯版（{tracks.replace(', ', ' / ')}）各 {per_backport} 个 ASM transformer | {coverage} |",
            f"| 检测引擎 | {capabilities} 项 `DetectorEngine` 检测能力，验收脚本中有 {algos} 个算法签名断言 | {coverage} |",
            f"| 漏洞回放矩阵 | {scenarios} 个场景，覆盖 {roots} 个 [Vulhub](https://github.com/vulhub/vulhub) 组件根（追踪 {cves} 个 CVE） | {vulhub} |",
            f"| 正常语料误报率 | {categories} 类共 {inputs} 条真实构造正常输入，`{fps} / {inputs}` 误报 | {fp} |",
            f"| 运行时支持 | JDK 8、11、17 各有独立构建，21 和 25 共用主 Agent；兼容 `javax.servlet` 与 `jakarta.servlet` | {agent} |",
        ]
    else:
        rows = [
            "| Metric | Value | Source |",
            "|---|---|---|",
            f"| Instrumented sink families | {hooks} ASM hook modules (`agent-jdk25`); {per_backport} ASM transformers per backport ({tracks}) | {coverage} |",
            f"| Detection engine | {capabilities} `DetectorEngine` capabilities, {algos} algorithm signatures asserted in acceptance scripts | {coverage} |",
            f"| Exploit replay suite | {scenarios} scenarios across {roots} [Vulhub](https://github.com/vulhub/vulhub) roots ({cves} CVEs tracked) | {vulhub} |",
            f"| Benign corpus precision | `{fps} / {inputs}` false positives across {categories} categories | {fp} |",
            f"| Supported JVMs | Builds for JDK 8, 11, 17, and a shared JDK 21/25 build (`javax.servlet` & `jakarta.servlet`) | {agent} |",
        ]
    return "\n".join([REGION_BEGIN, *rows, REGION_END])


def splice_region(text: str, region: str, path: Path) -> str:
    begins, ends = text.count(f"<!-- BEGIN GENERATED {REGION_SLUG} "), text.count(REGION_END)
    if begins != 1 or ends != 1:
        raise SystemExit(
            f"{path}: expected exactly 1 {REGION_SLUG} region, found {begins} BEGIN/{ends} END;"
            " add the BEGIN/END markers once"
        )
    start = text.index(f"<!-- BEGIN GENERATED {REGION_SLUG} ")
    end = text.index(REGION_END)
    if end < start:
        raise SystemExit(f"{path}: the {REGION_SLUG} END marker comes before its BEGIN marker")
    return text[:start] + region + text[end + len(REGION_END):]


def outputs() -> dict[Path, str]:
    out = {OUT: render()}
    for path, lang in README_REGIONS.items():
        out[path] = splice_region(path.read_text(encoding="utf-8"), render_metrics(lang), path)
    return out


def main() -> int:
    files = outputs()
    if "--check" in sys.argv:
        stale = [p for p, c in files.items() if not p.exists() or p.read_text(encoding="utf-8") != c]
        if stale:
            names = ", ".join(str(p.relative_to(REPO)) for p in stale)
            print(f"gen-detection-coverage: stale — {names}. Run"
                  " `python3 java-agent/scripts/gen-detection-coverage.py` and commit the result.", file=sys.stderr)
            return 1
        print(f"gen-detection-coverage: {len(files)} files up to date.")
        return 0
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
