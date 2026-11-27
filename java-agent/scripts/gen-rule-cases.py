#!/usr/bin/env python3
"""Write java-agent/docs/RULE-CASES.md from the rule cases in java-agent/rules/cases/.

  python3 java-agent/scripts/gen-rule-cases.py           rewrite the summary
  python3 java-agent/scripts/gen-rule-cases.py --check   exit non-zero when the summary is stale

It reads the case files, uncovered.toml and the catalogue's not_wired ids only, so it needs no agent build and no Docker. The
rule-cases probe (java-agent/probes/rule-cases) is what checks that the engines still do what the
files declare.
"""
from __future__ import annotations

import sys
from collections import Counter, defaultdict
from pathlib import Path

JAVA_AGENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(JAVA_AGENT / "probes" / "common"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rule_cases  # noqa: E402
import rule_catalogue  # noqa: E402

OUTPUT = JAVA_AGENT / "docs" / "RULE-CASES.md"
EFFECT_ORDER = ("block", "log", "none", "unreachable")


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def describe_input(case: rule_cases.Case) -> str:
    parts = []
    if case.control:
        parts.append("control " + ", ".join(f"{k}={v}" for k, v in case.control.items()))
    if case.request:
        r = case.request
        target = r["uri"] + (f"?{r['query']}" if r.get("query") else "")
        parts.append(f"{r['method']} {target}")
        extra = {k: v for k, v in r.get("headers", {}).items() if k not in ("User-Agent", "Accept")}
        extra.update(r.get("attributes", {}))
        if extra:
            parts.append(", ".join(f"{k}: {v}" for k, v in extra.items()))
    if case.op:
        args = ", ".join(" ".join(v) if isinstance(v, list) else v for k, v in case.args.items() if k != "api")
        api = f" ({case.args['api']})" if "api" in case.args else ""
        parts.append(f"{case.op}{api} {args}")
    text = "; ".join(parts)
    return text if len(text) <= 160 else text[:157] + "..."


def expectation(expect: rule_cases.Expect) -> str:
    text = expect.effect + (f" `{expect.rule}`" if expect.rule else "")
    return text + (f" (also {', '.join(f'`{a}`' for a in expect.also)})" if expect.also else "")


def render(cases: list[rule_cases.Case], uncovered: dict[str, dict[str, str]]) -> str:
    out = [
        "# Rule cases",
        "",
        "> **Generated** by `java-agent/scripts/gen-rule-cases.py` from `java-agent/rules/cases/*.toml`; do not edit.",
        "> `--check` fails `scripts/check-docs.py` when this file is stale.",
        "",
        "Each case is one input, the path that carries it into the agent, and what each engine does with it",
        "today: the primary agent (JDK 21 and 25) and the backport agents (Java 8, 11 and 17). The",
        "`rule-cases` probe runs every case on every agent line and fails when an engine does something",
        "else. How to run and add cases: [java-agent/AGENTS.md](../AGENTS.md#rules).",
        "",
        "Effects: **block** the agent stopped the operation and its event says block; **log** an event",
        "names the rule and the operation ran; **none** no event and the operation ran; **unreachable**",
        "this path cannot reach a rule for this input on that engine.",
        "",
    ]
    out += ["## Case files", "",
            "One file per rule id. Effects count the file's attack cases; rules are the ids those cases name.", "",
            "| Case file | Attack | Benign | Primary effects | Primary rules | Backport effects | Backport rules |",
            "|---|---:|---:|---|---|---|---|"]
    by_file: dict[str, list] = defaultdict(list)
    for case in cases:
        by_file[case.file].append(case)
    for name in sorted(by_file, key=str.lower):
        group = by_file[name]
        attacks = [c for c in group if c.kind == "attack"]
        row = [f"[{name}](../rules/cases/{name}.toml)", str(len(attacks)), str(len(group) - len(attacks))]
        for engine in rule_cases.ENGINES:
            effects = Counter(c.expect[engine].effect for c in attacks)
            row.append(", ".join(f"{e} {effects[e]}" for e in EFFECT_ORDER if effects[e]) or "-")
            rules = dict.fromkeys(r for c in attacks for r in c.expect[engine].ids())
            row.append(", ".join(f"`{r}`" for r in rules) or "-")
        out.append("| " + " | ".join(row) + " |")
    out.append("")
    for engine in rule_cases.ENGINES:
        attacks: dict[str, list] = defaultdict(list)
        files_of: dict[str, set[str]] = defaultdict(set)
        for case in cases:
            expect = case.expect[engine]
            for rule in expect.ids():
                files_of[rule].add(case.file)
                if case.kind == "attack":
                    attacks[rule].append(expect.effect if rule == expect.rule else f"{expect.effect} (also)")
        benign = Counter(case.file for case in cases if case.kind == "benign")
        title = "Primary rule ids" if engine == "primary" else "Backport rule families (without the line prefix)"
        out += [f"## {title}", "", "Each id that some case names on this engine: the attack cases that name it, the benign "
                "cases in the same files, and the effects those attack cases declare.", "",
                "| Rule id | Attack cases | Benign cases | Declared effects | Case files |",
                "|---|---:|---:|---|---|"]
        for rule in sorted(files_of, key=str.lower):
            effects = Counter(attacks[rule])
            declared = ", ".join(f"{effect} {effects[effect]}" for effect in
                                 sorted(effects, key=lambda e: (EFFECT_ORDER.index(e.split()[0]), e)))
            files = ", ".join(f"[{f}](../rules/cases/{f}.toml)" for f in sorted(files_of[rule]))
            out.append(f"| `{rule}` | {len(attacks[rule])} | {sum(benign[f] for f in files_of[rule])} | "
                       f"{declared or '-'} | {files} |")
        out.append("")
        if uncovered[engine]:
            out += ["Not covered on this engine, from [uncovered.toml](../rules/cases/uncovered.toml) and, for the ids marked "
                    "`not wired`, from the `not_wired` object of the [catalogue](../rules/general.json):", ""]
            groups: dict[str, list[str]] = defaultdict(list)
            for rule, reason in uncovered[engine].items():
                groups[reason].append(rule)
            for reason, rules in groups.items():
                out.append(f"- {reason}: {', '.join(f'`{r}`' for r in sorted(rules, key=str.lower))}")
            out.append("")

    differing = [c for c in cases if c.kind == "attack" and c.expect["primary"].effect != c.expect["backport"].effect]
    out += ["## Where the engines differ", "",
            "Attack cases whose effect differs between the primary and the backports, grouped by the pair of effects.",
            ""]
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for case in differing:
        groups[(case.expect["primary"].effect, case.expect["backport"].effect)].append(case)
    for (primary, backport), group in sorted(groups.items(), key=lambda g: (EFFECT_ORDER.index(g[0][0]),
                                                                         EFFECT_ORDER.index(g[0][1]))):
        out += [f"### Primary {primary}, backports {backport}", "",
                "| Case | Path | Input | Primary | Backports | Why |", "|---|---|---|---|---|---|"]
        for case in sorted(group, key=lambda c: c.id):
            why = "; ".join(f"{e}: {case.expect[e].why}" for e in rule_cases.ENGINES if case.expect[e].why)
            out.append(f"| [{case.file}](../rules/cases/{case.file}.toml) `{case.name}` | {case.via} | "
                       f"`{cell(describe_input(case))}` | {expectation(case.expect['primary'])} | "
                       f"{expectation(case.expect['backport'])} | {cell(why)} |")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    text = render(rule_cases.load(), rule_catalogue.with_not_wired(rule_cases.load_uncovered()))
    if "--check" in sys.argv[1:]:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != text:
            print(f"{OUTPUT.relative_to(JAVA_AGENT.parent)} is stale; run python3 java-agent/scripts/gen-rule-cases.py",
                  file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(JAVA_AGENT.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
