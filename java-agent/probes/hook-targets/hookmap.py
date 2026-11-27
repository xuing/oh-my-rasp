"""Reading and checking the recorded hook maps.

Shared by check.py (the probe), java-agent/scripts/gen-hook-targets.py (the summary document) and
java-agent/probes/test_hook_targets.py. Nothing here runs Java or touches the network.

A recorded map (recorded/primary.txt, recorded/backport.txt) is the output of HookMap.java under a
banner: comment lines, then one row per hooked method,

    group:artifact version class method descriptor -> agent owner.method [xN] @ unit[,unit]

where xN is the number of calls to that agent method the unit adds (absent for one) and a unit is a primary HookModule or a backport Java{N}...Transformer. A row that the agent's
shared call-site visitors make in any class carries the unit COMMON instead of a module.
"""
from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIBRARIES = HERE / "libraries.toml"
ALLOWLIST = HERE / "allowlist.toml"
HOOK_MISS = HERE / "hook-miss.toml"
RECORDED = HERE / "recorded"
COMMON = "(shared visitors)"
FAMILIES = ("primary", "backport")
TOKEN = "{N}"  # stands for 8, 11 or 17 in a backport's names

BANNER = {
    "primary": "the primary agent (agent-jdk25: the jdk21 and jdk25 lines)",
    "backport": "the backport agents (agent-java8, agent-java11, agent-java17), whose version token is written {N}",
}


@dataclass(frozen=True)
class Library:
    group: str
    artifact: str
    versions: tuple[str, ...]
    why: str
    none: dict

    @property
    def id(self) -> str:
        return f"{self.group}:{self.artifact}"


@dataclass(frozen=True)
class Row:
    library: str
    version: str
    cls: str
    method: str
    descriptor: str
    callee: str
    units: tuple[str, ...]
    calls: int = 1


@dataclass(frozen=True)
class HookMap:
    units: tuple[str, ...]
    stats: str
    rows: tuple[Row, ...]
    chain: tuple[str, ...] = ()


def load_libraries(path: Path = LIBRARIES) -> list[Library]:
    data = tomllib.loads(path.read_text())
    return [Library(row["group"], row["artifact"], tuple(row["versions"]), row["why"], dict(row.get("none", {})))
            for row in data["library"]]


def load_allowlist(path: Path = ALLOWLIST) -> dict[str, dict[str, str]]:
    data = tomllib.loads(path.read_text())
    return {family: dict(data.get(family, {})) for family in FAMILIES}


def banner(family: str, update_command: str) -> str:
    return (f"# Hook map of {BANNER[family]}.\n"
            "# The libraries and versions are those of libraries.toml.\n"
            f"# Generated; never edit by hand. Regenerate with `{update_command}` and review the diff.\n"
            "# One row per method that an agent unit rewrites to call back into the agent:\n"
            "#   library version class method descriptor -> agent owner.method [xN] @ unit[,unit]\n"
            "# xN is how many calls to that agent method the unit adds to the method (absent for one). A class under\n"
            "# META-INF/versions/N/ of a multi-release JAR carries that prefix. A `# chain:` line is a backport\n"
            "# transformer that adds something different after the transformers before it than on the original class.\n"
            f"# The unit {COMMON} is the call-site rewriting that applies to any class, not a hook on a named target.\n")


def normalise(text: str, track: str) -> str:
    """Replace a backport's version token (java8, Java8) with {N}; the primary has none."""
    if track == "main":
        return text
    text = re.sub(rf"io/ohmyrasp/agent/java{track}/", f"io/ohmyrasp/agent/java{TOKEN}/", text)
    return re.sub(rf"Java{track}(?=[A-Z])", f"Java{TOKEN}", text)


def parse(text: str) -> HookMap:
    units: tuple[str, ...] = ()
    stats = ""
    rows = []
    chain = []
    for line in text.splitlines():
        if line.startswith("# chain:"):
            chain.append(line[2:])
        elif line.startswith("# units"):
            units = tuple(line.split(":", 1)[1].split())
        elif line.startswith("# libraries:"):
            stats = line[2:]
        elif line and not line.startswith("#"):
            hook, units_text = line.rsplit(" @ ", 1)
            target, callee = hook.split(" -> ", 1)
            library, version, cls, method, descriptor = target.split(" ")
            calls = re.search(r" x(\d+)$", callee)
            if calls:
                callee = callee[:calls.start()]
            rows.append(Row(library, version, cls, method, descriptor, callee, tuple(units_text.split(",")),
                            int(calls[1]) if calls else 1))
    if not units:
        raise ValueError("no '# units' line: this is not a hook map")
    return HookMap(units, stats, tuple(rows), tuple(chain))


def named_rows(hook_map: HookMap) -> list[Row]:
    """Rows of hooks on named targets: everything except the shared call-site rewriting."""
    return [row for row in hook_map.rows if row.units != (COMMON,)]


def check_library_versions(libraries: list[Library], maps: dict[str, HookMap]) -> list[str]:
    """Every library version is hooked somewhere, or says in libraries.toml why not."""
    hooked = {(row.library, row.version) for hook_map in maps.values() for row in named_rows(hook_map)}
    problems = []
    for library in libraries:
        for version in library.versions:
            expected_none = library.none.get(version)
            if (library.id, version) in hooked and expected_none is not None:
                problems.append(f"{library.id} {version} is hooked, but libraries.toml lists it under `none`: {expected_none}")
            elif (library.id, version) not in hooked and expected_none is None:
                problems.append(f"{library.id} {version} has no hooked method on any agent line; "
                                "add it under `none` with a reason, or fix the hook")
        for version in library.none:
            if version not in library.versions:
                problems.append(f"{library.id} lists {version} under `none`, but not in `versions`")
    return problems


def check_units(maps: dict[str, HookMap], allowlist: dict[str, dict[str, str]]) -> list[str]:
    """Every hook family hooks a library method somewhere, or is on the allowlist with a reason.

    The allowlist is a floor: an entry for a unit that does hook something, or for one that no
    longer exists, fails too.
    """
    problems = []
    for family, hook_map in maps.items():
        used = {unit for row in named_rows(hook_map) for unit in row.units}
        allowed = allowlist[family]
        for unit in hook_map.units:
            if unit not in used and unit not in allowed:
                problems.append(f"{family}: {unit} hooks no method of any library in libraries.toml; "
                                "add the library it targets, or list the unit in allowlist.toml with the reason")
        for unit, reason in allowed.items():
            if not str(reason).strip():
                problems.append(f"{family}: allowlist entry {unit} has no reason")
            if unit not in hook_map.units:
                problems.append(f"{family}: allowlist entry {unit} names no unit of the agent; remove it")
            elif unit in used:
                problems.append(f"{family}: allowlist entry {unit} is no longer needed: it hooks a library method now; remove it")
    return problems


def runtime_class(cls: str) -> str:
    """The name a class has at run time: a multi-release entry loses its META-INF/versions/N/ prefix."""
    if cls.startswith("META-INF/versions/"):
        return cls.split("/", 3)[3]
    return cls


def family_of(unit: str) -> str:
    return "backport" if unit.startswith("Java" + TOKEN) else "primary"


@dataclass(frozen=True)
class MissPair:
    unit: str
    cls: str
    check: str
    why: str


def load_hook_miss(path: Path = HOOK_MISS) -> dict[tuple[str, str], MissPair]:
    """hook-miss.toml by (unit, class). A malformed entry raises: the file is reviewed input, not data to skip."""
    pairs: dict[tuple[str, str], MissPair] = {}
    for row in tomllib.loads(path.read_text()).get("pair", []):
        pair = MissPair(row["unit"], row["class"], row["check"], str(row.get("why", "")).strip())
        if pair.check not in ("absent", "never"):
            raise ValueError(f"hook-miss.toml: {pair.unit} {pair.cls}: check must be absent or never, not {pair.check!r}")
        if not pair.why:
            raise ValueError(f"hook-miss.toml: {pair.unit} {pair.cls} has no reason")
        if (pair.unit, pair.cls) in pairs:
            raise ValueError(f"hook-miss.toml: {pair.unit} {pair.cls} is listed twice")
        pairs[(pair.unit, pair.cls)] = pair
    return pairs


def callee_name(callee: str) -> str:
    """The agent method a recorded row's callee names, without its owner (which differs between agent lines) and
    without the ` (reflective)` mark: `io/ohmyrasp/agent/hook/OhMyRaspHooks.beforeX` is `beforeX`."""
    return callee.removesuffix(" (reflective)").rsplit(".", 1)[-1]


def expected_hooks(hook_map: HookMap) -> dict[tuple[str, str], dict[str, set[str]]]:
    """(unit, run-time class) -> each method (name + descriptor) the unit instruments there on some recorded version,
    with the names of the agent methods it calls from it."""
    pairs: dict[tuple[str, str], dict[str, set[str]]] = {}
    for row in named_rows(hook_map):
        for unit in row.units:
            if unit != "?":
                methods = pairs.setdefault((unit, runtime_class(row.cls)), {})
                methods.setdefault(row.method + row.descriptor, set()).add(callee_name(row.callee))
    return pairs


EXPECTATIONS = HERE.parent.parent / "shared" / "src" / "main" / "resources" / "META-INF" / "ohmyrasp" / "hook-expectations"


def expectation_table(family: str, hook_map: HookMap, hook_miss: dict[tuple[str, str], MissPair]) -> str:
    """The run-time table of the hook-miss report (io.ohmyrasp.agent.hookmiss.HookExpectations) for one family.

    Rows are `unit class check method=callee[,callee] ...`; the `#! family` line names the family, and the last line,
    `#! end rows=<n> sha256=<hex>`, carries the row count and the SHA-256 of every byte before it, so the agent can
    refuse a table that was cut or changed after it was generated."""
    lines = [f"# Generated by java-agent/scripts/gen-hook-targets.py from java-agent/probes/hook-targets/recorded/{family}.txt",
             "# and java-agent/probes/hook-targets/hook-miss.toml. Never edit by hand; regenerate and review the diff.",
             "# unit class check method=callee,... : the hook-miss report expects the unit to instrument one of these methods",
             "# of the class, calling from it one of the agent methods named after the = (see io.ohmyrasp.agent.hookmiss.HookExpectations).",
             f"#! family {family}"]
    rows = 0
    for (unit, cls), methods in sorted(expected_hooks(hook_map).items()):
        pair = hook_miss.get((unit, cls))
        if pair is not None and pair.check == "never":
            continue
        tokens = " ".join(f"{method}={','.join(sorted(callees))}" for method, callees in sorted(methods.items()))
        lines.append(f"{unit} {cls} {pair.check if pair else 'report'} {tokens}")
        rows += 1
    body = "\n".join(lines) + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return f"{body}#! end rows={rows} sha256={digest}\n"


def hook_miss_entry_problems(maps: dict[str, HookMap], hook_miss: dict[tuple[str, str], MissPair]) -> list[str]:
    """An entry of hook-miss.toml must name a pair the recorded maps of its family hook."""
    problems = []
    for (unit, cls), pair in sorted(hook_miss.items()):
        family = family_of(unit)
        if family in maps and (unit, cls) not in expected_hooks(maps[family]):
            problems.append(f"hook-miss.toml: {unit} hooks no method of {cls} in recorded/{family}.txt; remove the entry")
    return problems


@dataclass(frozen=True)
class Claim:
    unit: str
    cls: str
    library: str
    version: str
    named: int  # methods of the class with a name the unit looks for


def parse_miss_run(text: str) -> tuple[list[Claim], set[tuple[str, str, str, str, str]]]:
    """The output of HookMissCheck.java: `claimed unit class library version named` and `report unit class library version reason`."""
    claims, reports = [], set()
    for line in text.splitlines():
        fields = line.split(" ")
        if fields[0] == "claimed":
            claims.append(Claim(fields[1], fields[2], fields[3], fields[4], int(fields[5])))
        elif fields[0] == "report":
            reports.add(tuple(fields[1:6]))
    return claims, reports


def derived_misses(claims: list[Claim], hook_map: HookMap, hook_miss: dict[tuple[str, str], MissPair]) -> tuple[set, set]:
    """From the recorded map: the (unit, class, library, version) a correct run-time report writes, and the pairs
    hook-miss.toml exempts on recorded versions (to find entries no version needs)."""
    hooked = {(unit, runtime_class(row.cls), row.library, row.version) for row in named_rows(hook_map) for unit in row.units}
    expected, exempted = set(), set()
    for claim in claims:
        key = (claim.unit, claim.cls, claim.library, claim.version)
        if key in hooked:
            continue
        pair = hook_miss.get((claim.unit, claim.cls))
        if pair is not None and pair.check == "absent" and claim.named == 0:
            exempted.add((claim.unit, claim.cls))
        else:
            expected.add(key)
    return expected, exempted


def load_recorded(directory: Path = RECORDED) -> dict[str, HookMap]:
    return {family: parse((directory / f"{family}.txt").read_text()) for family in FAMILIES}
