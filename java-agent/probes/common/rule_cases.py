"""The rule-case schema: load java-agent/rules/cases/*.toml and say what is wrong with them.

One file per rule id (the primary id, or the backport family for a backport-only family) holds
[[case]] entries. A case names an input, the path that carries it into the agent, and what each
engine does with it today:

    [[case]]
    name = "passwd-read-outside-request"    # unique in the file
    kind = "attack"                          # or "benign"
    via = "sink"                             # sink | request | request-sink
    op = "file.read"                         # the sink (absent when via = "request")
    args = { path = "/etc/passwd" }          # the sink's arguments; see OPS
    completes_with = ["NamingException"]     # optional: exceptions (simple names, or a superclass's) that end
                                             #   the sink when it runs and the agent let it through
                                             #   (an exception that agent code threw never counts; leave it out
                                             #   of a benign case whose operation has no reason to fail)
    properties = { "ohmyrasp.x" = "..." }    # optional: extra system properties for the agent JVM
    control = { outside_request = "log" }    # optional: top-level members of a control document; the agent
                                             #   then runs in daemon-managed mode and reads {"mode": "block", ...}
                                             #   from the control file at start, instead of standalone block mode
    setup = { files = ["{tmp}/a/b.txt"] }    # optional: files created before the JVM starts
    stubs = ["org.example.Gadget"]           # optional: empty serializable classes of these names on the class path

    [case.request]                           # via = request or request-sink
    method = "GET"
    uri = "/download"
    query = "file=%2Fetc%2Fpasswd"           # parameters come from the query unless params is given
    params = { file = ["/etc/passwd"] }
    headers = { "User-Agent" = "curl/8.0" }  # a value or a list of values
    body = "{\"a\":1}"                       # optional: the request body, which the handler reads like an application
    body_api = "reader"                      # stream (the default) or reader: getInputStream() or getReader()
    attributes = { "javax.servlet.include.request_uri" = "/WEB-INF/web.xml" }

    [case.primary]                           # and [case.backport]
    effect = "block"                         # block | log | none | unreachable
    rule = "readFile_unwanted"               # block and log only; a backport rule is the family, unprefixed
    also = ["request_path_confusion"]        # other rule ids the engine reports for the same input
    why = "..."                              # one sentence; required on an attack whose effect is not block

Placeholders in string values: {tmp} is the case's own temporary directory, {port} the driver's
loopback listener, {classes} the directory holding the class the listener serves.

This module knows the schema only. java-agent/scripts/test_rule_cases.py checks rule ids against the
catalogue and the coverage ratchet; the rule-cases probe runs the cases.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CASES = Path(__file__).resolve().parents[2] / "rules" / "cases"
UNCOVERED = "uncovered.toml"
ENGINES = ("primary", "backport")
KINDS = ("attack", "benign")
VIAS = ("sink", "request", "request-sink")
EFFECTS = ("block", "log", "none", "unreachable")
# op -> (required args, optional args)
OPS = {
    "process.exec": ({"argv"}, {"api"}),
    "file.read": ({"path"}, {"api"}),
    "file.write": ({"path"}, {"api", "content"}),
    "file.list": ({"path"}, {"api"}),
    "file.delete": ({"path"}, {"api"}),
    "jndi.lookup": ({"name"}, set()),
    "net.open": ({"url"}, set()),
    "classloader.remote": ({"url", "class"}, set()),
    "deserialize": ({"class"}, set()),
    "xml.parse": ({"document"}, set()),
    "archive.extract": ({"entry", "path"}, set()),
    "base64.decode": ({"input"}, {"api"}),
    "jdbc.connect": ({"url"}, set()),
    "sql.execute": ({"sql"}, set()),
    "beans.decode": ({"document"}, set()),
    "java.compile": ({"source"}, {"api"}),
    "xpath.evaluate": ({"expression"}, set()),
}
CASE_KEYS = {"name", "kind", "via", "op", "args", "completes_with", "properties", "control", "setup", "stubs", "request",
             *ENGINES}
REQUEST_KEYS = {"method", "uri", "query", "params", "headers", "attributes", "body", "body_api"}
EXPECT_KEYS = {"effect", "rule", "also", "why"}


@dataclass(frozen=True)
class Expect:
    effect: str
    rule: str | None = None
    also: tuple[str, ...] = ()
    why: str = ""

    def ids(self) -> tuple[str, ...]:
        return ((self.rule,) if self.rule else ()) + self.also


@dataclass(frozen=True)
class Case:
    file: str            # the rule id the file is named for
    name: str
    kind: str
    via: str
    op: str | None
    args: dict
    request: dict | None
    expect: dict          # engine -> Expect
    completes_with: tuple[str, ...] = ()
    properties: dict = field(default_factory=dict)
    control: dict = field(default_factory=dict)
    setup: dict = field(default_factory=dict)
    stubs: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return f"{self.file}::{self.name}"


class SchemaError(Exception):
    pass


def _expect(where: str, kind: str, raw) -> tuple[Expect | None, list[str]]:
    if not isinstance(raw, dict):
        return None, [f"{where}: missing or not a table"]
    errors = [f"{where}: unknown key {k}" for k in raw if k not in EXPECT_KEYS]
    effect = raw.get("effect")
    if effect not in EFFECTS:
        return None, errors + [f"{where}: effect must be one of {', '.join(EFFECTS)}"]
    rule, also, why = raw.get("rule"), raw.get("also", []), raw.get("why", "")
    if effect in ("block", "log") and not (isinstance(rule, str) and rule):
        errors.append(f"{where}: effect {effect} names the rule")
    if effect in ("none", "unreachable") and (rule or also):
        errors.append(f"{where}: effect {effect} names no rule")
    if not isinstance(also, list) or not all(isinstance(a, str) and a for a in also):
        errors.append(f"{where}: also is a list of rule ids")
        also = []
    if not isinstance(why, str):
        errors.append(f"{where}: why is a sentence")
        why = ""
    if kind == "attack" and effect != "block" and not why.strip():
        errors.append(f"{where}: an attack expected to {effect} says why")
    if kind == "benign" and effect != "none":
        errors.append(f"{where}: a benign case expects none")
    return Expect(effect, rule or None, tuple(also), why.strip()), errors


def _strings(value) -> bool:
    return isinstance(value, str) or (isinstance(value, list) and value and all(isinstance(v, str) for v in value))


def parse(file: str, text: str) -> tuple[list[Case], list[str]]:
    """Cases of one file and every schema error in it."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return [], [f"{file}: {error}"]
    errors = [f"{file}: unknown top-level key {k}; a case file holds [[case]] entries" for k in data if k != "case"]
    cases, names = [], set()
    for index, raw in enumerate(data.get("case", [])):
        where = f"{file}::{raw.get('name', f'#{index + 1}')}"
        errors += [f"{where}: unknown key {k}" for k in raw if k not in CASE_KEYS]
        name, kind, via, op = raw.get("name"), raw.get("kind"), raw.get("via"), raw.get("op")
        if not isinstance(name, str) or not name or not name.replace("-", "").isalnum() or name != name.lower():
            errors.append(f"{where}: name is lower-case words joined by hyphens")
        elif name in names:
            errors.append(f"{where}: name repeated in the file")
        names.add(name)
        if kind not in KINDS:
            errors.append(f"{where}: kind must be attack or benign")
        if via not in VIAS:
            errors.append(f"{where}: via must be one of {', '.join(VIAS)}")
        args = raw.get("args", {})
        if via == "request":
            if op is not None or args:
                errors.append(f"{where}: a request-only case has no op or args")
        elif op not in OPS:
            errors.append(f"{where}: op must be one of {', '.join(OPS)}")
        else:
            required, optional = OPS[op]
            missing = required - set(args)
            unknown = set(args) - required - optional
            if missing:
                errors.append(f"{where}: {op} needs args {', '.join(sorted(missing))}")
            if unknown:
                errors.append(f"{where}: {op} takes no args {', '.join(sorted(unknown))}")
            for key, value in args.items():
                if key == "argv":
                    if not (isinstance(value, list) and value and all(isinstance(v, str) for v in value)):
                        errors.append(f"{where}: argv is a non-empty list of strings")
                elif not isinstance(value, str):
                    errors.append(f"{where}: arg {key} is a string")
        request = raw.get("request")
        if via in ("request", "request-sink"):
            if not isinstance(request, dict):
                errors.append(f"{where}: via {via} needs [case.request]")
                request = None
            else:
                errors += [f"{where}: request has no key {k}" for k in request if k not in REQUEST_KEYS]
                if not isinstance(request.get("method"), str) or not isinstance(request.get("uri"), str):
                    errors.append(f"{where}: request needs method and uri")
                if "body" in request and not isinstance(request["body"], str):
                    errors.append(f"{where}: request body is a string")
                if "body_api" in request and (request["body_api"] not in ("stream", "reader") or "body" not in request):
                    errors.append(f"{where}: request body_api is stream or reader, and needs a body")
                for key in ("params", "headers", "attributes"):
                    table = request.get(key, {})
                    if not isinstance(table, dict) or not all(_strings(v) for v in table.values()):
                        errors.append(f"{where}: request {key} maps names to a string or a list of strings")
        elif request is not None:
            errors.append(f"{where}: via sink carries no request")
        for key in ("properties", "control", "setup"):
            if not isinstance(raw.get(key, {}), dict):
                errors.append(f"{where}: {key} is a table")
        control = raw.get("control", {}) if isinstance(raw.get("control", {}), dict) else {}
        if "mode" in control or not all(isinstance(v, str) for v in control.values()):
            errors.append(f"{where}: control holds string members other than mode (the probe writes mode block)")
        files = raw.get("setup", {}).get("files", []) if isinstance(raw.get("setup", {}), dict) else []
        if not isinstance(files, list) or not all(isinstance(f, str) and f.startswith("{tmp}/") for f in files):
            errors.append(f"{where}: setup files are paths under {{tmp}}/")
        stubs = raw.get("stubs", [])
        if not isinstance(stubs, list) or not all(isinstance(n, str) and n.replace(".", "").replace("_", "").isalnum()
                                                  and "." in n for n in stubs):
            errors.append(f"{where}: stubs is a list of binary class names in a package")
            stubs = []
        completes = raw.get("completes_with", [])
        if not isinstance(completes, list) or not all(isinstance(n, str) and n.isidentifier() for n in completes):
            errors.append(f"{where}: completes_with is a list of exception simple names")
            completes = []
        expect = {}
        for engine in ENGINES:
            value, problems = _expect(f"{where} [{engine}]", kind, raw.get(engine))
            errors += problems
            if value:
                expect[engine] = value
        if len(expect) == len(ENGINES) and kind in KINDS and via in VIAS:
            cases.append(Case(file=file, name=name, kind=kind, via=via, op=op, args=dict(args),
                              request=request, expect=expect, completes_with=tuple(completes),
                              properties=dict(raw.get("properties", {})), control=dict(control),
                              setup=dict(raw.get("setup", {})),
                              stubs=tuple(stubs)))
    if not data.get("case"):
        errors.append(f"{file}: holds no [[case]]")
    return cases, errors


def case_files(directory: Path = CASES) -> list[Path]:
    return sorted(p for p in directory.glob("*.toml") if p.name != UNCOVERED)


def load(directory: Path = CASES) -> list[Case]:
    """Every case; SchemaError lists every problem when any file is invalid."""
    cases, errors = [], []
    for path in case_files(directory):
        found, problems = parse(path.stem, path.read_text(encoding="utf-8"))
        cases += found
        errors += problems
    if errors:
        raise SchemaError("\n".join(errors))
    return cases


def load_uncovered(directory: Path = CASES) -> dict[str, dict[str, str]]:
    """engine -> {rule id: reason} from uncovered.toml ([[primary]] / [[backport]] groups of ids and a reason)."""
    data = tomllib.loads((directory / UNCOVERED).read_text(encoding="utf-8"))
    result: dict[str, dict[str, str]] = {engine: {} for engine in ENGINES}
    for engine in ENGINES:
        for group in data.get(engine, []):
            for rule in group["ids"]:
                if rule in result[engine]:
                    raise SchemaError(f"{UNCOVERED}: {engine} {rule} is listed twice")
                result[engine][rule] = group["reason"]
    return result


def covered(cases: list[Case]) -> dict[str, set[str]]:
    """engine -> the rule ids that some file shows caught (an attack expecting it to block or log) and spared (a benign case)."""
    with_benign = {c.file for c in cases if c.kind == "benign"}
    result: dict[str, set[str]] = {engine: set() for engine in ENGINES}
    for c in cases:
        if c.kind != "attack" or c.file not in with_benign:
            continue
        for engine in ENGINES:
            expect = c.expect[engine]
            if expect.effect in ("block", "log"):
                result[engine].add(expect.rule)
    return result
