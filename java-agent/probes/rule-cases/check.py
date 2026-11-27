#!/usr/bin/env python3
"""Run every rule case in java-agent/rules/cases on the packaged agent and compare each engine's effect and rule id.

A case counts only when the line under test started in its JVM: the driver reports the line the launcher
published (system property ohmyrasp.agent.line) and the line's own start output must be in the JVM's
output or event file, or the case is broken. The events a case is judged on are the ones written between
the driver's marks around the operation, not everything in the event file.

Each case JVM also logs class loading (-verbose:class on Java 8, -Xlog:class+load on 9 and later), and the
driver loads a marker class at each end of the operation. A class of the agent (io.ohmyrasp.agent.) that
loads between the marks loaded inside a hook or a transformer, inside the JDK call the hook instruments,
where loading a class can re-enter the hook: the case fails and names the class, on every line, since each loads at
start, from the list in its JAR, what its hooks use. A lambda's hidden class (Foo$$Lambda/0x...) cannot be on a list,
because it does not exist until its call site first runs; those are counted per source class and reported, and they
fail a case only on the lines in ENFORCED_HIDDEN (none of the primary's: it still has lambdas and method references).

A case with a request body is also broken when a detection's message or details (but the keys that hold a rule's
own constants) carry text of that body: a string value of a JSON body three characters or longer, a value of a form
body, an eight-character piece of any other body, or the canary password the JSON cases carry. An event names the
body field its evidence came from, never the value.

Known gaps of the class-load check: hooks reached while the driver sets up, before its first mark (the
listener socket, the stub JDBC driver), are not checked; and no case exercises the completion of
HttpClient.sendAsync, the restoration of a nested servlet dispatch, MyBatis mapper substitution or the
RocketMQ filter-server attribution, so a class first loaded on those paths would pass. The preload list
(every class of the module and of :shared) covers them all the same.
"""
from __future__ import annotations

import argparse
import json
import os
import re
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
AGENT_PACKAGE = "io.ohmyrasp.agent."
# The class name in a class-load line: "[Loaded <name> from <source>]" (Java 8 -verbose:class) or
# "[<decorations>][class,load] <name> source: <source>" (Java 9 and later -Xlog:class+load).
LOADED = re.compile(r"^\[Loaded (\S+) from |\[class,load\]\s+(\S+)")
MARKS = ("RuleCaseDriver$OperationStart", "RuleCaseDriver$OperationEnd")
# The guard fails a case on both families: a named class of the agent that loads during the operation is a
# class missing from the line's preload list. A lambda's hidden class is reported separately, and fails a case
# only on the families named in ENFORCED_HIDDEN: the backports compile without invokedynamic call sites, so any
# hidden class there is a regression; the primary still has lambdas and method references in code its hooks reach.
ENFORCED_ENGINES = ("backport", "primary")
ENFORCED_HIDDEN = ("backport",)
HIDDEN = re.compile(r"^(.*)\$\$Lambda(\$\d+)?/(0x[0-9a-f]+|\d+)$")


CANARY = "hunter2-Secret"
# Detail keys whose values are a rule's own constants (BodyEvidence.RULE_CONSTANTS): not request text.
RULE_CONSTANTS = {"decision_basis", "policy_basis", "process_operation", "argument_count", "multipart_source",
                  "archive_policy_sha256", "method"}
PLACEHOLDER = re.compile(r"\{\w+\}")


def body_texts(body: str, content_type: str) -> list[str]:
    """The texts of a request body that no event may carry (see the module docstring)."""
    texts = [CANARY]
    try:
        document = json.loads(body)
    except ValueError:
        document = None
    if document is not None and not isinstance(document, (str, int, float, bool)):
        def walk(value):
            if isinstance(value, dict):
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)
            elif isinstance(value, str) and len(value) >= 3:
                texts.append(value)
        walk(document)
    elif "x-www-form-urlencoded" in content_type.lower():
        texts += [value for _, value in parse_qsl(body.strip(), keep_blank_values=True) if len(value) >= 3]
    else:
        text = body.strip()
        texts += [text[i:i + 8] for i in range(0, max(0, len(text) - 7))]
    # A value with a placeholder the driver fills ({port}) is checked by its literal pieces.
    pieces = []
    for text in texts:
        parts = PLACEHOLDER.split(text)
        pieces += [text] if len(parts) == 1 else [part for part in parts if len(part) >= 8]
    return pieces


def body_text_in_events(case: rule_cases.Case, events: list[dict]) -> str | None:
    """The first body text a detection carries, as 'rule: field', or None."""
    request = case.request or {}
    if "body" not in request:
        return None
    content_type = next((v for k, v in (request.get("headers") or {}).items() if k.lower() == "content-type"), "")
    texts = body_texts(request["body"], content_type)
    for event in events:
        fields = [("message", event.get("message", ""))]
        fields += [(key, value) for key, value in (event.get("details") or {}).items()
                   if key not in RULE_CONSTANTS and isinstance(value, str)]
        for key, value in fields:
            for text in texts:
                if text in value:
                    return f"{event.get('algorithm')}: {key} carries {text[:24]!r}"
    return None


def class_load_options(major: int, tmp: Path) -> list[str]:
    """JVM options that log class loading: to standard output on Java 8, to a file on 9 and later."""
    return ["-verbose:class"] if major <= 8 else [f"-Xlog:class+load:file={tmp / 'class-load.log'}"]


def late_agent_classes(text: str) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """The agent classes the log shows loading between the driver's two marks, in order, as (named classes, source
    classes of hidden lambda classes, one entry per hidden class); None when a mark is missing."""
    names = [m.group(1) or m.group(2) for m in map(LOADED.search, text.splitlines()) if m]
    if MARKS[0] not in names or MARKS[1] not in names:
        return None
    between = [name for name in names[names.index(MARKS[0]) + 1:names.index(MARKS[1])] if name.startswith(AGENT_PACKAGE)]
    # A lambda's class name carries a counter and an address that differ between runs: keep its source class.
    hidden = [HIDDEN.match(name) for name in between]
    return (tuple(name for name, m in zip(between, hidden) if not m),
            tuple(m.group(1) for m in hidden if m))


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
    late: tuple[str, ...] = ()  # named agent classes that loaded during the operation
    hidden: tuple[str, ...] = ()  # source class of each hidden lambda class that loaded during the operation


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
        if "body" in r:
            pairs += [("request.body", sub(r["body"]) * r.get("body_repeat", 1)),
                      ("request.bodyApi", r.get("body_api", "stream")), ("request.bodyRead", r.get("body_read", "all"))]
            if "body_chunk" in r:
                pairs.append(("request.bodyChunk", str(r["body_chunk"])))
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


def run_case(case, agent, classpath, classes, work, track, major) -> tuple[Actual, str]:
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
    # The driver's report is a file, not a line of standard output: on Java 8 the class-load log shares
    # standard output and can split a line printed there.
    report = tmp / "rulecase-report.txt"
    if case.control:
        # Daemon-managed: the agent reads the control document at start, as it reads the daemon's.
        control = tmp / "control.json"
        control.write_text(json.dumps({"mode": "block", **case.control}, indent=2) + "\n")
        settings = ["-Dohmyrasp.standalone=false", f"-Dohmyrasp.control={control}"]
    else:
        settings = ["-Dohmyrasp.standalone=true", "-Dohmyrasp.mode=block", "-Dohmyrasp.control=none"]
    command = ["java", "-Xverify:all", f"-javaagent:{agent}", *settings,
               "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}", *props,
               *class_load_options(major, tmp), f"-Drulecase.report={report}",
               "-cp", classpath, "RuleCaseDriver"]
    try:
        run = subprocess.run(command, input=spec_lines(case, tmp, classes), capture_output=True, text=True,
                             timeout=TIMEOUT, cwd=tmp)
    except subprocess.TimeoutExpired:
        return Actual("broken", None, (), f"driver did not finish in {TIMEOUT}s"), ""
    output = run.stdout + run.stderr
    reported = report.read_text() if report.exists() else ""
    result_lines = [line for line in reported.splitlines() if line.startswith("RULECASE\t")]
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

    actual = classify(case, result, [(family(e["algorithm"]), e["action"]) for e in events])
    leak = body_text_in_events(case, events)
    if leak:
        actual = Actual("broken", actual.rule, actual.also, f"an event carries request-body text ({leak})")
    load_log = tmp / "class-load.log"
    late = late_agent_classes(load_log.read_text(errors="replace") if load_log.exists() else run.stdout)
    if late is None:
        return Actual("broken", None, (), "the class-load log has no operation marks"), output
    actual.late, actual.hidden = late
    return actual, output


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
    elif handler == "yes" and result.get("body", "").startswith("blocked"):
        # The agent's exception ended the application's own read of the body: the read decided the body.
        outcome, note = "blocked", f"in the handler, while it read the body ({result['body']})"
    elif handler == "yes":
        outcome, note = ("ran", "handler ran") if case.via == "request" else (op, f"in the handler: {ending}")
        if "body" in result:
            note += f", body {result['body']}"
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
    major = agent_track.java_major()
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
            results = list(pool.map(lambda c: run_case(c, agent, classpath, remote, work, track, major), cases))
        failures = 0
        late_failures = 0
        late_by_class: dict[str, list[str]] = {}
        hidden_by_source: dict[str, list[int]] = {}   # per source class, how many hidden classes each case loaded
        hidden_cases: dict[str, list[str]] = {}
        enforced = engine in ENFORCED_ENGINES
        hidden_enforced = engine in ENFORCED_HIDDEN
        for case, (actual, output) in zip(cases, results):
            expect = case.expect[engine]
            if args.print_actual:
                print(as_toml(case, engine, actual) + "\n")
                continue
            late = list(dict.fromkeys(actual.late))
            for name in late:
                late_by_class.setdefault(name, []).append(case.id)
            for source in dict.fromkeys(actual.hidden):
                hidden_by_source.setdefault(source, []).append(actual.hidden.count(source))
                hidden_cases.setdefault(source, []).append(case.id)
            if late and enforced:
                late_failures += 1
                print(f"LATE {case.id}: agent classes loaded during the operation: {', '.join(late)}")
            if actual.hidden and hidden_enforced:
                late_failures += 1
                print(f"HIDDEN {case.id}: lambda classes created during the operation, from: "
                      f"{', '.join(dict.fromkeys(actual.hidden))}")
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
    affected = len({case_id for ids in late_by_class.values() for case_id in ids})
    print(f"{len(late_by_class)} agent class(es) loaded during an operation, in {affected} of {len(cases)} case(s)"
          + ("" if enforced else f"; reported, not enforced on the {engine} line (see ENFORCED_ENGINES)"))
    for name, ids in sorted(late_by_class.items()):
        print(f"  late {name}: {len(ids)} case(s), first {ids[0]}")
    # The most hidden classes one case loaded from a source class is the least number of lambda sites it has that
    # the cases reach; the same class from two cases may be two sites or one.
    sites = {source: max(counts) for source, counts in hidden_by_source.items()}
    print(f"{sum(sites.values())} hidden lambda class(es) at least, from {len(sites)} source class(es), created during "
          "an operation" + ("" if hidden_enforced else f"; reported, not enforced on the {engine} line "
                                                       "(see ENFORCED_HIDDEN)"))
    for source, count in sorted(sites.items()):
        print(f"  hidden {source}: {count} lambda class(es) in one case, {len(hidden_cases[source])} case(s), "
              f"first {hidden_cases[source][0]}")
    if failures or late_failures:
        raise SystemExit(f"{failures} rule case(s) differ from what their file declares; "
                         f"{late_failures} loaded an agent class during the operation")


if __name__ == "__main__":
    main()
