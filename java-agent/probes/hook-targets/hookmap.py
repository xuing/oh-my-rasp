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

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIBRARIES = HERE / "libraries.toml"
ALLOWLIST = HERE / "allowlist.toml"
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


def load_recorded(directory: Path = RECORDED) -> dict[str, HookMap]:
    return {family: parse((directory / f"{family}.txt").read_text()) for family in FAMILIES}
