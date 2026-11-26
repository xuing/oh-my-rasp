#!/usr/bin/env python3
"""Run every rule case in java-agent/rules/cases on the packaged agent and compare each engine's effect and rule id.

A case counts only when the line under test started in its JVM: the driver reports the line the launcher
published (system property ohmyrasp.agent.line) and the line's own start output must be in the JVM's
output or event file, or the case is broken. The events a case is judged on are the ones written between
the driver's marks around the operation, not everything in the event file.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
sys.path.insert(0, str(COMMON))
import agent_track  # noqa: E402
import rule_cases  # noqa: E402
from servlet_fixture import api_jar  # noqa: E402

TIMEOUT = 90


def engine_of(agent: Path) -> tuple[str, str | None]:
    """("backport", "8"|"11"|"17") or ("primary", None): the line probes/run.py names, or the one line the JAR holds."""
    track = agent_track.track(agent)
    return ("backport", track) if track else ("primary", None)


@dataclass
class Actual:
    effect: str            # block | log | none, or broken
    rule: str | None
    also: tuple[str, ...]
    note: str               # how the operation ended, for the reader


def spec_lines(case: rule_cases.Case, tmp: Path, classes: Path) -> str:
    def sub(value: str) -> str:
        return value.replace("{tmp}", str(tmp)).replace("{classes}", str(classes))

    pairs: list[tuple[str, str]] = [("via", case.via), ("tmp", str(tmp)), ("classes", str(classes))]
    if case.op:
        pairs.append(("op", case.op))
    for key, value in case.args.items():
        if isinstance(value, list):
            pairs += [(f"{key}.{i}", sub(v)) for i, v in enumerate(value)]
        else:
            pairs.append((key, sub(value)))
    if case.completes_with:
        pairs.append(("completes_with", ",".join(case.completes_with)))
    if case.request:
        r = case.request
        pairs += [("request.method", r["method"]), ("request.uri", sub(r["uri"]))]
        query = r.get("query")
        if query is not None:
            pairs.append(("request.query", sub(query)))
        params = r.get("params")
        if params is None:
            params = {}
            for name, value in parse_qsl(sub(query or ""), keep_blank_values=True):
                params.setdefault(name, []).append(value)
        for prefix, table in (("param", params), ("header", r.get("headers", {})), ("attr", r.get("attributes", {}))):
            index = 0
            for name, values in table.items():
                for value in ([values] if isinstance(values, str) else values):
                    pairs += [(f"{prefix}.{index}.name", name), (f"{prefix}.{index}.value", sub(value))]
                    index += 1
    return "".join(f"{k}={v.encode().hex()}\n" for k, v in pairs)


def run_case(case, agent, classpath, classes, work, track) -> tuple[Actual, str]:
    tmp = work / "cases" / f"{case.file}--{case.name}"
    tmp.mkdir(parents=True)
    for name in case.setup.get("files", []):
        path = Path(name.replace("{tmp}", str(tmp)))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("rule case fixture\n")
    if case.stubs:
        stub_dir = tmp / "stubs"
        sources = []
        for name in case.stubs:
            package, _, simple = name.rpartition(".")
            source = stub_dir / "src" / f"{simple}.java"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(f"package {package};\n/** A stand-in with the listed name; it does nothing. */\n"
                              f"public class {simple} implements java.io.Serializable {{\n"
                              "  private static final long serialVersionUID = 1L;\n}\n")
            sources.append(str(source))
        compiled = subprocess.run(["javac", "-d", str(stub_dir), *sources], capture_output=True, text=True)
        if compiled.returncode:
            return Actual("broken", None, (), "stub classes did not compile"), compiled.stdout + compiled.stderr
        classpath = os.pathsep.join((classpath, str(stub_dir)))
    log = tmp / "events.jsonl"
    props = [f"-D{k}={str(v).replace('{tmp}', str(tmp))}" for k, v in case.properties.items()]
    command = ["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true", "-Dohmyrasp.mode=block",
               "-Dohmyrasp.control=none", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}", *props,
               "-cp", classpath, "RuleCaseDriver"]
    try:
        run = subprocess.run(command, input=spec_lines(case, tmp, classes), capture_output=True, text=True,
                             timeout=TIMEOUT, cwd=tmp)
    except subprocess.TimeoutExpired:
        return Actual("broken", None, (), f"driver did not finish in {TIMEOUT}s"), ""
    output = run.stdout + run.stderr
    result_lines = [line for line in run.stdout.splitlines() if line.startswith("RULECASE\t")]
    if run.returncode or not result_lines:
        return Actual("broken", None, (), f"driver exited {run.returncode}"), output
    result = dict(part.split("=", 1) for part in result_lines[-1].split("\t")[1:])
    logged = log.read_bytes() if log.exists() else b""
    not_started = agent_not_started(track, result, output + logged.decode(errors="replace"))
    if not_started:
        return Actual("broken", None, (), not_started), output
    events = []
    # Only what the operation wrote: an event from before the driver marked its start (the agent's startup, a
    # class the JVM loaded on the way) belongs to nothing the case did.
    start, end = int(result["log_start"]), int(result["log_end"])
    for line in logged[start:end].decode().splitlines():
        event = json.loads(line)
        if event.get("kind") == "detection" or event.get("event") == "ohmyrasp-detection":
            events.append(event)
    prefix = f"java{track}_" if track else ""

    def family(rule: str) -> str:
        return rule[len(prefix):] if prefix and rule.startswith(prefix) else rule

    return classify(case, result, [(family(e["algorithm"]), e["action"]) for e in events]), output


def agent_not_started(track: str | None, result: dict, text: str) -> str | None:
    """Why the line under test did not start in this JVM, or None when it did. A JVM without the agent lets
    everything through, so a case that expects "none" would otherwise pass on a launcher that skipped or failed."""
    expected = agent_track.PRIMARY if track is None else track
    name = agent_track.LINE_NAMES[expected]
    if result.get("agent_line") != name:
        return (f"the {name} line did not start: the launcher published ohmyrasp.agent.line="
                f"'{result.get('agent_line', '')}' (no agent, or another line)")
    started = {agent_track.start_track(line) for line in text.splitlines()}
    if expected not in started:
        return f"the {name} line published its name but its start line is in neither the JVM's output nor the event file"
    return None


def classify(case, result: dict, events: list[tuple[str, str]]) -> Actual:
    entry, handler, op, ending = result.get("entry"), result.get("handler"), result.get("op"), result.get("ending", "")
    if case.via == "sink":
        outcome, note = op, ending
    elif handler == "yes":
        outcome, note = ("ran", "handler ran") if case.via == "request" else (op, f"in the handler: {ending}")
    elif entry in ("blocked", "blocked-redirect"):
        outcome = "blocked"
        note = f"at request entry ({'redirected to ' + result.get('redirect', '') if entry == 'blocked-redirect' else result.get('entry_ending', '')})"
    else:
        outcome, note = "error", f"handler did not run; entry {entry}: {result.get('entry_ending', '')}"
    rules = list(dict.fromkeys(rule for rule, _ in events))
    blocks = list(dict.fromkeys(rule for rule, action in events if action == "block"))
    if outcome == "error" or outcome not in ("ran", "blocked"):
        return Actual("broken", None, tuple(rules), f"the operation failed without the agent: {note}")
    if outcome == "blocked":
        if not blocks:
            return Actual("broken", None, tuple(rules), f"blocked, but no event says block: {note}")
        return Actual("block", blocks[-1], tuple(r for r in rules if r != blocks[-1]), note)
    if blocks:
        return Actual("broken", blocks[0], tuple(rules), f"an event says block, but the operation ran: {note}")
    if rules:
        return Actual("log", rules[0], tuple(rules[1:]), note)
    return Actual("none", None, (), note)


def matches(expect: rule_cases.Expect, actual: Actual) -> bool:
    if actual.effect == "broken":
        return False
    if expect.effect in ("none", "unreachable"):
        return actual.effect == "none"
    if expect.effect != actual.effect:
        return False
    return {expect.rule, *expect.also} == {actual.rule, *actual.also} and (
        expect.rule == actual.rule or expect.effect == "log")


def describe(expect: rule_cases.Expect | Actual) -> str:
    text = expect.effect + (f" {expect.rule}" if expect.rule else "")
    return text + (f" (also {', '.join(expect.also)})" if expect.also else "")


def as_toml(case, engine: str, actual: Actual) -> str:
    lines = [f"# {case.id}: {actual.note}", f"[case.{engine}]", f'effect = "{actual.effect}"']
    if actual.rule:
        lines.append(f'rule = "{actual.rule}"')
    if actual.also:
        lines.append("also = [" + ", ".join(f'"{r}"' for r in actual.also) + "]")
    old = case.expect[engine]
    if old.why and actual.effect != "block":
        lines.append(f"why = {json.dumps(old.why)}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--api-dir", type=Path, help="directory holding the staged servlet API JAR")
    parser.add_argument("--file", action="append", default=[], help="run only this case file (rule id); repeatable")
    parser.add_argument("--case", action="append", default=[], help="run only cases with this name; repeatable")
    parser.add_argument("--print-actual", action="store_true",
                        help="print what this engine did for each case as a [case.<engine>] table, and do not fail")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4, help="driver JVMs at once")
    parser.add_argument("--cases-dir", type=Path, default=rule_cases.CASES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    engine, track = engine_of(agent)
    cases = rule_cases.load(args.cases_dir)
    known_files = {c.file for c in cases}
    unknown = [f for f in args.file if f not in known_files]
    if unknown:
        raise SystemExit(f"no case file {', '.join(unknown)} in {args.cases_dir}")
    cases = [c for c in cases if (not args.file or c.file in args.file) and (not args.case or c.name in args.case)]
    if not cases:
        raise SystemExit("no case selected")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="rule-cases-") as directory:
        work = Path(directory)
        classes, remote = work / "classes", work / "remote"
        api = api_jar("javax", work, args.api_dir)
        for output, sources, extra in ((classes, ["RuleCaseDriver.java", "StubStatement.java"], ["-cp", str(api)]),
                                       (remote, ["RemoteGreeting.java"], [])):
            output.mkdir()
            compiled = subprocess.run(["javac", *extra, "-d", str(output), *(str(HERE / s) for s in sources)],
                                      capture_output=True, text=True)
            if compiled.returncode:
                raise SystemExit(compiled.stdout + compiled.stderr)
        classpath = os.pathsep.join((str(classes), str(api)))
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            results = list(pool.map(lambda c: run_case(c, agent, classpath, remote, work, track), cases))
        failures = 0
        for case, (actual, output) in zip(cases, results):
            expect = case.expect[engine]
            if args.print_actual:
                print(as_toml(case, engine, actual) + "\n")
                continue
            if not matches(expect, actual):
                failures += 1
                print(f"FAIL {case.id} ({case.kind}, via {case.via}) on the {engine}\n"
                      f"  declared: {describe(expect)}\n  actual:   {describe(actual)}\n  ended:    {actual.note}")
                if actual.effect == "broken" and output.strip():
                    print("  driver output:\n    " + "\n    ".join(output.strip().splitlines()[-15:]))
    elapsed = time.monotonic() - started
    label = f"{engine}{' java' + track if track else ''}"
    if args.print_actual:
        print(f"# {len(cases)} case(s) on the {label} agent in {elapsed:.1f}s")
        return
    print(f"{len(cases) - failures}/{len(cases)} rule case(s) matched on the {label} agent in {elapsed:.1f}s "
          f"({args.jobs} at once)")
    if failures:
        raise SystemExit(f"{failures} rule case(s) differ from what their file declares")


if __name__ == "__main__":
    main()
