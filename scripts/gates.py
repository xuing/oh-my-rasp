#!/usr/bin/env python3
"""Which checks to run after a change, and a way to run them.

  gates.py list                 every gate, the paths that trigger it, its commands
  gates.py changed [--base REF] the gates the current change triggers, and why
  gates.py run --changed        run those gates (add --slow for the long ones)
  gates.py run GATE [GATE..]    run named gates

"The current change" is everything that differs from the merge base with REF
(default origin/main, then main): committed, staged, unstaged and untracked.
A gate lists the commands CI runs for the same paths; scripts/test_gates.py
fails when a gate's command is no longer in the workflow it names.
"""
from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALL_LINES = "java8,java11,java17,java17-on-21,jdk21,jdk25"
GO = '"$(awk \'$1 == "FROM" && $2 ~ /^golang:/ { print $2; exit }\' api/Dockerfile)"'


@dataclass(frozen=True)
class Gate:
    id: str
    what: str
    paths: tuple[str, ...]      # path prefixes, or fnmatch patterns when they contain *; () means every change
    commands: tuple[str, ...]   # run from the repo root
    ci: str = ""                # workflow under .github/workflows that runs the same commands
    local: str = ""             # when ci is empty: how CI covers the same ground
    needs: str = "python3"
    slow: bool = False          # left out of --changed unless --slow


GATES = (
    Gate("docs", "docs match their sources of truth; Java files stay under the size limit", (),
         ("python3 scripts/check-java-size.py",
          "python3 -m unittest discover -s scripts -p 'test_check_docs.py'",
          "python3 scripts/check-docs.py"), ci="docs.yml"),
    Gate("gates", "this table still matches the CI workflows",
         ("scripts/gates.py", "scripts/test_gates.py", ".github/workflows/"),
         ("python3 -m unittest discover -s scripts -p 'test_gates.py'",), ci="docs.yml"),
    Gate("probe-registry", "probe manifests, agent lines, Gradle tasks and the CI matrix agree",
         ("java-agent/probes/", ".github/workflows/agent.yml", "java-agent/*build.gradle.kts", "java-agent/*/build.gradle.kts"),
         ("python3 -m unittest discover -s java-agent/probes -p 'test_*.py'",), ci="agent.yml"),
    Gate("agent-evidence", "offline Vulhub evidence tooling", ("java-agent/scripts/", "java-agent/acceptance/"),
         ("python3 -m unittest discover -s java-agent/scripts/evidence -p 'test_*.py'",), ci="agent.yml"),
    Gate("agent-parity", "the backport lines differ only where recorded; false-positive carve-outs exist in every line",
         ("java-agent/agent-", "java-agent/scripts/check-backport-drift.py", "java-agent/scripts/backport-drift."),
         ("python3 java-agent/scripts/check-backport-drift.py",
          "cd java-agent && bash scripts/check-detector-parity.sh"), ci="agent.yml"),
    Gate("agent-primary", "JDK 25 agent: unit tests and the benign corpus",
         ("java-agent/agent-jdk25/", "java-agent/shared/", "java-agent/scripts/FpReport.java", "java-agent/contracts/"),
         ("java-agent/scripts/check-agent.sh",), needs="docker",
         local="agent.yml runs the same tests with `gradle check` and compares the corpus report"),
    Gate("agent-backports", "Java 8, 11 and 17 agents: the shared unit tests on each line, no new invokedynamic call sites",
         ("java-agent/agent-java8/", "java-agent/agent-java11/", "java-agent/agent-java17/", "java-agent/shared/",
          "java-agent/backport-tests/", "java-agent/gradle/", "java-agent/contracts/", "java-agent/scripts/check-dynamic-calls.py",
          "java-agent/scripts/dynamic-calls.baseline.json"),
         ("java-agent/scripts/check-agent.sh --line java8,java11,java17",), needs="docker",
         local="agent.yml runs the same tests with `gradle check`, then check-dynamic-calls.py --check"),
    Gate("agent-tooling", "unit tests of the Java agent checkers, and the rule-case files against the catalogue",
         ("java-agent/scripts/", "java-agent/rules/", "java-agent/probes/common/rule_cases.py"),
         ("python3 -m unittest discover -s java-agent/scripts -p 'test_check_dynamic_calls.py'",
          "python3 -m unittest discover -s java-agent/scripts -p 'test_check_backport_drift.py'",
          "python3 -m unittest discover -s java-agent/scripts -p 'test_rule_cases.py'"), ci="agent.yml"),
    Gate("agent-probes", "every packaged probe on every agent line, each on its own JDK, with the line's JAR and the universal JAR",
         ("java-agent/agent-", "java-agent/shared/", "java-agent/probes/"),
         (f"java-agent/scripts/check-agent.sh --line {ALL_LINES} all",
          f"java-agent/scripts/check-agent.sh --artifact all --line {ALL_LINES} all"), needs="docker", slow=True,
         local="agent.yml runs probes/run.py for each row of the runtime-compatibility matrix, "
               "with each line's JAR and then with --artifact all"),
    Gate("api", "Go control-plane API tests, including the generated-bindings freshness test", ("api/",),
         (f"docker run --rm -v \"$PWD/api\":/src -w /src {GO} go test ./...",), needs="docker",
         local="ohmyrasp-control.yml runs `go test ./...` with the integration services up"),
    Gate("console", "React console: i18n parity, build, lint, types, end-to-end", ("console/",),
         ("cd console && npm ci", "cd console && npm run build", "cd console && npm test"),
         ci="ohmyrasp-control.yml", needs="node"),
    Gate("daemon", "Rust daemon: format, lints, tests (the tests read the agent-daemon contract examples)",
         ("daemon/", "java-agent/contracts/"),
         ("cd daemon && cargo fmt --check", "cd daemon && cargo clippy --locked --all-targets -- -D warnings",
          "cd daemon && cargo test --locked"), ci="daemon.yml", needs="cargo"),
    Gate("deploy", "Helm manifests and observability assets render and validate", ("deploy/", "docker-compose.yml"),
         ("deploy/scripts/validate-helm-manifests.sh", "deploy/scripts/validate-observability-assets.sh"),
         ci="ohmyrasp-control.yml", needs="helm"),
)
BY_ID = {gate.id: gate for gate in GATES}


def git(*args: str) -> list[str]:
    return subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True).stdout.split("\n")


def changed_paths(base: str | None) -> list[str]:
    candidates = [base] if base else ["origin/main", "main"]
    for ref in candidates:
        probe = subprocess.run(["git", "-C", str(ROOT), "merge-base", "HEAD", ref], capture_output=True, text=True)
        if probe.returncode == 0:
            merge_base = probe.stdout.strip()
            break
    else:
        sys.exit(f"cannot find a merge base with {' or '.join(candidates)}; pass --base")
    paths = {*git("diff", "--name-only", merge_base), *git("ls-files", "--others", "--exclude-standard")}
    return sorted(p for p in paths if p)


def triggers(gate: Gate, path: str) -> bool:
    return not gate.paths or any(fnmatch.fnmatch(path, p) if "*" in p else path.startswith(p) for p in gate.paths)


def select(paths: list[str], slow: bool) -> list[tuple[Gate, str]]:
    """Gates the paths trigger, each with the first path that triggered it."""
    chosen = []
    for gate in GATES:
        hit = next((p for p in paths if triggers(gate, p)), None)
        if hit and (slow or not gate.slow):
            chosen.append((gate, hit))
    # A changed probe gets its own run on every line instead of waiting for the slow sweep.
    probe_root = ROOT / "java-agent" / "probes"
    probes = sorted({p.split("/")[2] for p in paths if p.startswith("java-agent/probes/") and p.count("/") >= 3})
    probes = [name for name in probes if (probe_root / name / "check.py").is_file()
              and "manual =" not in ((probe_root / name / "probe.toml").read_text()
                                     if (probe_root / name / "probe.toml").is_file() else "")]
    if len(probes) > 3 and not any(gate.id == "agent-probes" for gate, _ in chosen):
        chosen.append((BY_ID["agent-probes"], f"{len(probes)} probe directories"))
    elif len(probes) <= 3:
        for probe in probes:
            chosen.append((Gate(f"probe:{probe}", f"the {probe} probe on every line it applies to", (),
                                (f'java-agent/scripts/check-agent.sh --line "$(python3 java-agent/probes/run.py lines {probe})" {probe}',),
                                needs="docker"),
                           f"java-agent/probes/{probe}/"))
    return chosen


def run(gates: list[Gate]) -> int:
    failed = []
    for gate in gates:
        print(f"== {gate.id}: {gate.what}", flush=True)
        start = time.monotonic()
        for command in gate.commands:
            print(f"$ {command}", flush=True)
            if subprocess.run(["bash", "-c", command], cwd=ROOT).returncode:
                failed.append(gate.id)
                break
        print(f"== {gate.id} {'FAILED' if gate.id in failed else 'ok'} in {time.monotonic() - start:.0f}s\n", flush=True)
    if failed:
        print(f"{len(failed)} gate(s) failed: {', '.join(failed)}")
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list")
    for name in ("changed", "run"):
        p = sub.add_parser(name)
        p.add_argument("--base", help="ref to diff against (default: origin/main, then main)")
        p.add_argument("--slow", action="store_true", help="include the slow gates")
        if name == "run":
            p.add_argument("--changed", action="store_true", help="run the gates the current change triggers")
            p.add_argument("gates", nargs="*", choices=[*BY_ID, []], metavar="GATE")
    args = parser.parse_args()
    if args.action == "list":
        for gate in GATES:
            print(f"{gate.id}{'  (slow)' if gate.slow else ''}: {gate.what}")
            print(f"    on:    {', '.join(gate.paths) or 'every change'}")
            for command in gate.commands:
                print(f"    run:   {command}")
            print(f"    needs: {gate.needs};  CI: {gate.ci or gate.local}")
        return
    if args.action == "changed" or args.changed:
        paths = changed_paths(args.base)
        chosen = select(paths, args.slow)
        print(f"{len(paths)} changed path(s) trigger {len(chosen)} gate(s):")
        for gate, hit in chosen:
            print(f"  {gate.id:16} because of {hit}")
        skipped = [g.id for g in GATES if g.slow and not args.slow and any(triggers(g, p) for p in paths)
                   and all(g.id != chosen_gate.id for chosen_gate, _ in chosen)]
        if skipped:
            print(f"  not selected (slow, add --slow): {', '.join(skipped)}")
        if args.action == "changed":
            return
        sys.exit(run([gate for gate, _ in chosen]))
    if not args.gates:
        parser.error("name at least one gate, or pass --changed")
    sys.exit(run([BY_ID[name] for name in args.gates]))


if __name__ == "__main__":
    main()
