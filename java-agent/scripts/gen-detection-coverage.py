#!/usr/bin/env python3
"""Generate docs/DETECTION-COVERAGE.md from the agent sources and test suite.

This is the single source of truth for "what OhMyRASP can detect". It is
derived, not written by hand, so it stays correct as hooks, detectors, and
acceptance scenarios are added. Re-run it after changing any of:

  * agent/src/main/java/io/ohmyrasp/agent/asm/HookRegistry.java   (hook families)
  * agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/       (detector classes)
  * acceptance/vulhub/*/*.sh                                      (verified scenarios)
  * acceptance/runtime/jdk25.sh  (its required_algorithms array)
  * probes/*/                    (primary rules a packaged-agent probe names)
  * rules/*.json                 (rule scope descriptions, and the "not_wired" ids)

It also owns the "By the numbers" region of the root README.md and
README.zh-CN.md, between these markers (one region per file):

  <!-- BEGIN GENERATED metrics (java-agent/scripts/gen-detection-coverage.py) ... -->
  <!-- END GENERATED metrics -->

A primary rule id that no hook module can reach is "not wired" (rules/general.json, checked against the sources by
scripts/test_rule_cases.py). No count here includes one; the report lists them in a section of their own.

Hand-written docs must not restate these counts; link to this report instead.

Usage:  python3 scripts/gen-detection-coverage.py [--check]
        --check exits non-zero if any generated output is stale (for CI).
"""
from __future__ import annotations

import functools
import json
import re
import sys
from pathlib import Path

# The docs checker's tests load this file by path, so the sibling module is not importable by default.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import acceptance_scripts  # noqa: E402
import detector_entry_points  # noqa: E402
import rule_catalogue  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent-jdk25" / "src" / "main" / "java" / "io" / "ohmyrasp" / "agent"
ACCEPTANCE = acceptance_scripts.ACCEPTANCE
PROBES = ROOT / "probes"
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
    """Distinct public detect* entry points across the detector classes."""
    return detector_entry_points.capabilities()


@functools.cache
def _named_in_scripts() -> frozenset[str]:
    algos: set[str] = set()
    for script in acceptance_scripts.runtime_and_vulhub_scripts(ACCEPTANCE):
        algos |= rule_catalogue.asserted(script.read_text(encoding="utf-8", errors="ignore"))
    return frozenset(algos)


def asserted_algorithms() -> list[str]:
    """Rule ids the acceptance scripts assert: each catalogue id written in a script as a whole token, except a
    not wired one (a script that names it reaches it through the playground servlet, which calls its entry directly)."""
    return sorted(_named_in_scripts() - rule_catalogue.not_wired().keys())


ARRAY = "required_algorithms"
# `required_algorithms=(` or `+=(`, optionally declared; the rest of the line may hold entries.
ARRAY_ASSIGN = re.compile(rf"^\s*(?:(?:declare|local|typeset)(?:\s+-\w+)*\s+)?{ARRAY}(\+?)=\((.*)$")
ARRAY_READ = re.compile(rf"\$\{{#?{ARRAY}\[[@*]\]\}}")
ARRAY_ENTRY = re.compile(r"""(["']?)([A-Za-z]\w*)\1""")
COMMENT = re.compile(r"(?:^|\s)#.*")


def parse_required_algorithms(text: str, name: str) -> list[str]:
    """The ids in a script's required_algorithms array: one `=(...)` assignment and any `+=(...)` appends.

    Entries may be quoted and followed by comments; the closing parenthesis may sit anywhere. A use of
    the array this parser does not read exits with the line, so the generated list is never short.
    """
    required: list[str] = []
    assigned = False
    open_at = 0
    for no, raw in enumerate(text.split("\n"), start=1):
        line = COMMENT.sub("", raw)
        if not open_at:
            assign = ARRAY_ASSIGN.match(line)
            if not assign:
                if ARRAY in ARRAY_READ.sub("", line):
                    raise SystemExit(f"{name}:{no}: cannot read this use of {ARRAY}: {raw.strip()}")
                continue
            if not assign.group(1):
                if assigned or required:
                    raise SystemExit(f"{name}:{no}: {ARRAY} is assigned after it already holds entries;"
                                     " use one `=(...)` and `+=(...)` appends after it")
                assigned = True
            open_at, line = no, assign.group(2)
        body, closed, rest = line.partition(")")
        for word in body.split():
            entry = ARRAY_ENTRY.fullmatch(word)
            if not entry:
                raise SystemExit(f"{name}:{no}: cannot read {ARRAY} entry `{word}`; write a rule id")
            required.append(entry.group(2))
        if closed:
            if rest.strip():
                raise SystemExit(f"{name}:{no}: cannot read `{rest.strip()}` after the closing parenthesis")
            open_at = 0
    if open_at:
        raise SystemExit(f"{name}:{open_at}: {ARRAY}=( is never closed")
    if not assigned:
        raise SystemExit(f"{name}: the {ARRAY}=( ... ) array was not found")
    return list(dict.fromkeys(required))


def jdk25_required_algorithms() -> list[str]:
    """The required_algorithms array of the JDK 25 runtime suite, in script order."""
    script = ACCEPTANCE / "runtime" / "jdk25.sh"
    required = parse_required_algorithms(script.read_text(encoding="utf-8"), str(script.relative_to(REPO)))
    if unknown := [r for r in required if r not in rule_catalogue.primary_ids()]:
        raise ValueError(f"{script.name} requires rules missing a scope description: {unknown}")
    return required


def probe_checked_rules() -> dict[str, list[str]]:
    """Primary rule id -> the packaged-agent probes whose sources name it as a string literal."""
    primary = rule_catalogue.primary_ids()
    found: dict[str, set[str]] = {}
    for probe in sorted(p for p in PROBES.iterdir() if (p / "check.py").is_file()):
        for src in (*probe.rglob("*.py"), *probe.rglob("*.java")):
            for name in set(re.findall(r'"(\w+)"', src.read_text(encoding="utf-8"))) & primary:
                found.setdefault(name, set()).add(probe.name)
    return {name: sorted(probes) for name, probes in sorted(found.items())}


def vulnerability_matrix() -> list[tuple[str, str]]:
    """(target, jdk) for each end-to-end vulhub acceptance scenario."""
    rows: list[tuple[str, str]] = []
    for script in acceptance_scripts.vulhub_scripts(ACCEPTANCE):
        stem = acceptance_scripts.legacy_stem(script)
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
    emitted: dict[str, set[str]] = {}
    for track, names in rule_catalogue.backport_findings().items():
        for name in sorted(names):
            family = name.removeprefix(track + "_")
            emitted.setdefault(track, set()).add(family)
            names_of = families.setdefault(family, [])
            if name not in names_of:
                names_of.append(name)
    # The backport lines are separate source trees that must decide alike: a rule one line emits, all emit.
    if gaps := {family: sorted(track for track, ids in emitted.items() if family not in ids)
                for family in families if any(family not in ids for ids in emitted.values())}:
        raise ValueError("Backport lines emit different rule ids. Missing: "
                         + "; ".join(f"{family} in {', '.join(tracks)}" for family, tracks in sorted(gaps.items())))
    documented = general["backports"].keys() | product["backports"].keys()
    if documented != families.keys():
        raise ValueError(f"Backport rule scope catalog differs from emitted families: {sorted(documented ^ families.keys())}")

    not_wired = rule_catalogue.not_wired().keys()
    lines = []
    for track, title, identifiers in (
        ("primary", "Primary agent", {key: [key] for key in primary if key not in not_wired}),
        ("backports", "Backport agents", families),
    ):
        lines.extend([f"### {title}", "", "| Algorithm identifier | Cross-product evidence | Product or component dependency |", "|---|---|---|"])
        for family, names in sorted(identifiers.items()):
            ids = ", ".join(f"`{name}`" for name in names)
            lines.append(f"| {ids} | {general[track].get(family, '—')} | {product[track].get(family, '—')} |")
        lines.append("")
    return lines


def not_wired_section() -> list[str]:
    """The "Defined, not wired" section: each primary rule id no hook module can reach, and why."""
    rules = ROOT / "rules"
    described = {}
    for name in ("general.json", "product.json"):
        for rule, text in json.loads((rules / name).read_text(encoding="utf-8"))["primary"].items():
            described.setdefault(rule, []).append(text)
    probes = probe_checked_rules()
    lines = [
        "## Defined, not wired",
        "",
        "These primary rule ids have a description in the catalog and code behind them, but no hook module injects a",
        "call that reaches that code, so the packaged agent cannot report them on a protected application. Unit",
        "tests call their detectors; the playground servlet and a probe's stub servlet call their `OhMyRaspHooks`",
        "entry methods directly, which is how the suites in the last column reach them. No count in this report or in the README",
        "includes them. The list is the `not_wired` object of the [general catalog](../rules/general.json), checked",
        "against the sources by `scripts/test_rule_cases.py`.",
        "",
        "| Rule id | Why no hook reaches it | Scope | Exercised only through |",
        "|---|---|---|---|",
    ]
    for rule, reason in sorted(rule_catalogue.not_wired().items(), key=lambda kv: kv[0].lower()):
        through = []
        if rule in _named_in_scripts():
            through.append("the JDK 25 runtime suite, via the playground servlet")
        through += [f"the [{p}](../probes/{p}/) probe" for p in probes.get(rule, [])]
        lines.append(f"| `{rule}` | {reason} | {' '.join(described[rule])} | {', '.join(through) or '—'} |")
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
    w(f"| Detector capabilities (public `detect*` entry points) | {len(capabilities)} |")
    w(f"| Algorithm signatures asserted in acceptance scripts | {len(algos)} |")
    w(f"| End-to-end vulnerability acceptance scenarios | {len(matrix)} |")
    w(f"| JDK lines exercised | {len([j for j in by_jdk if j != 'unknown'])} |")
    w(f"| Primary rule ids defined, not wired (in none of the counts above) | {len(rule_catalogue.not_wired())} |")
    w("")

    w("## Hook families")
    w("")
    w("Instrumentation points registered by `HookRegistry.defaults()`. Each module")
    w("rewrites a family of risky call sites and routes them to a detector class.")
    w("")
    w("| Family | Hook module |")
    w("|--------|-------------|")
    for module in families:
        family = module[: -len("HookModule")]
        w(f"| {family} | `{module}` |")
    w("")

    w("## Detector capabilities")
    w("")
    w(f"The detector classes in `agent-jdk25/src/main/java/io/ohmyrasp/agent/detect/` expose **{len(capabilities)}**")
    w("distinct public `detect*` entry points. Hooks call the class that owns each one;")
    w("`DetectorEngine.detectRequest` runs the request-level detectors in a fixed first-match order.")
    w("")
    w("| Class | Entry points |")
    w("|-------|--------------|")
    for owner, names in detector_entry_points.by_class().items():
        w(f"| `{owner}` | " + " · ".join(f"`detect{n}`" for n in names) + " |")
    w("")
    skipped = detector_entry_points.not_wired_by_class()
    stubs = detector_entry_points.stubs_by_class()
    w(f"Not counted: **{sum(len(names) for names in skipped.values())}** public `detect*` entry points that serve only rules")
    w("[defined, not wired](#defined-not-wired): " + ", ".join(
        f"`{owner}` " + " · ".join(f"`detect{n}`" for n in names) for owner, names in skipped.items()) + ".")
    w("")
    w(f"Also not counted: **{sum(len(names) for names in stubs.values())}** compatibility stubs whose every overload only returns an")
    w("empty result, so they decide nothing (the rule each is named for is decided by another entry point): " + ", ".join(
        f"`{owner}` " + " · ".join(f"`detect{n}`" for n in names) for owner, names in stubs.items()) + ".")
    w("")

    w("## Rule scope")
    w("")
    w("The index covers literal detection IDs in the primary engine and hooks, reviewed computed IDs, and named findings in the Java backports. A row with both columns populated has distinct branches or a product-specific exclusion. General request indicators still need runtime evidence to establish an effect.")
    w("")
    w("The descriptions live in the [general catalog](../rules/general.json) and [product-specific catalog](../rules/product.json). Scope describes applicability. Policy selection continues to use the exact event ID. The primary table leaves out the rule ids that no hook reaches, which have their own section below.")
    w("")
    lines.extend(rule_scope_tables())
    lines.extend(not_wired_section())
    w("## Algorithm signatures asserted in acceptance scripts")
    w("")
    w("Each rule id of the [catalog](../rules/) that a runtime or Vulhub acceptance script writes as a whole token:")
    w("as the algorithm of an expected event, as the argument of a helper that checks one, or in a list the script")
    w("loops over, such as the JDK 25 suite's `required_algorithms`. Runtime evidence for individual environments is")
    w("tracked in the [Vulhub coverage ledger](../../docs/development/vulhub-coverage.md).")
    w("")
    for algorithm in algos:
        w(f"- `{algorithm}`")
    w("")

    required = jdk25_required_algorithms()
    not_wired = rule_catalogue.not_wired()
    w("## Rules the JDK 25 runtime suite requires")
    w("")
    w("[`acceptance/runtime/jdk25.sh`](../acceptance/runtime/jdk25.sh) fails unless the protected log of every Tomcat")
    w("line it runs holds a block event for each identifier in its `required_algorithms` array:")
    w("")
    for algorithm in required:
        if algorithm not in not_wired:
            w(f"- `{algorithm}`")
    w("")
    skipped_required = [algorithm for algorithm in required if algorithm in not_wired]
    w(f"The array also names {len(skipped_required)} rules [defined, not wired](#defined-not-wired). The suite reaches them")
    w("through the playground servlet, which calls their hook entry methods itself, so a block event for one shows that")
    w("the detector and the policy work, not that a hook reaches it: "
      + ", ".join(f"`{a}`" for a in skipped_required) + ".")
    w("")
    w("### Other primary rules a probe checks")
    w("")
    w("These primary-agent rules are not in that array. A [packaged-agent probe](../probes/run.py) names each one")
    w("in its check; the probe runs against the built agent JAR.")
    w("")
    w("| Rule | Probes |")
    w("|------|--------|")
    for name, probes in probe_checked_rules().items():
        if name not in required and name not in not_wired:
            w(f"| `{name}` | " + ", ".join(f"[{p}](../probes/{p}/)" for p in probes) + " |")
    w("")

    w("## Tested vulnerability matrix")
    w("")
    w("End-to-end acceptance scenarios that run a real vulnerable application under")
    w("the agent. Counts by JDK line:")
    w("")
    w("| JDK | Scenarios |")
    w("|-----|----------:|")
    for jdk in JDK_ORDER + [j for j in sorted(by_jdk) if j not in JDK_ORDER]:
        if jdk in by_jdk:
            w(f"| {jdk} | {len(by_jdk[jdk])} |")
    w(f"| **total** | **{len(matrix)}** |")
    w("")
    scripts = acceptance_scripts.vulhub_scripts(ACCEPTANCE)
    boundary = [s for s in scripts if acceptance_scripts.is_boundary(s, ACCEPTANCE)]
    legacy = [s for s in boundary if "legacy" in s.name.lower()]
    w(f"{len(scripts) - len(boundary)} of the {len(matrix)} scripts run the exploit against a JVM an agent line supports.")
    w(f"The other {len(boundary)} show a boundary and no block: the {len(legacy)} `java6-legacy` and `java7-legacy`")
    w("scripts show an agent line skipping on an old JVM, which then runs unprotected, and the setup or licence")
    w("scripts show a payload held behind a setup state.")
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
    unwired = len(rule_catalogue.not_wired())
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
            f"| 检测引擎 | {capabilities} 项检测能力，验收脚本中有 {algos} 个算法签名断言；另有 {unwired} 个规则 ID 已定义但未接入 hook，不计入 | {coverage} |",
            f"| 漏洞回放矩阵 | {scenarios} 个场景，覆盖 {roots} 个 [Vulhub](https://github.com/vulhub/vulhub) 组件根（追踪 {cves} 个 CVE） | {vulhub} |",
            f"| 正常语料误报率 | {categories} 类共 {inputs} 条真实构造正常输入，`{fps} / {inputs}` 误报 | {fp} |",
            f"| 运行时支持 | JDK 8、11、17 各有独立构建，21 和 25 共用主 Agent；兼容 `javax.servlet` 与 `jakarta.servlet` | {agent} |",
        ]
    else:
        rows = [
            "| Metric | Value | Source |",
            "|---|---|---|",
            f"| Instrumented sink families | {hooks} ASM hook modules (`agent-jdk25`); {per_backport} ASM transformers per backport ({tracks}) | {coverage} |",
            f"| Detection engine | {capabilities} detector capabilities, {algos} algorithm signatures asserted in acceptance scripts; {unwired} rule ids are defined but not wired, and not counted | {coverage} |",
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
