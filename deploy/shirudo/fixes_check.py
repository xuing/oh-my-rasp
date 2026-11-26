#!/usr/bin/env python3
"""The advisories the universal package lists as `fixes`, and what backs each of them.

deploy/shirudo/fixes.toml names each advisory ID with the Vulhub acceptance script that shows the
agent stopping its exploit. gen-readmes.py writes the `fixes = [...]` line of
deploy/shirudo/ohmyrasp/Beefile from that file and fails its --check when the Beefile differs or
when an entry no longer holds. An entry holds when:

  - `replayed` is an ISO date, not in the future, and `replayed_with` names the universal JAR
    (`ohmyrasp-agent-all.jar` or `ohmyrasp.jar`): the date of the last replay-fixes.sh run against it;
  - the ID is one shirudo accepts (1 to 255 bytes of letters, digits, `.`, `_`, `:`, `-`), listed once,
    and there are at most 16 entries;
  - each script is tracked under java-agent/acceptance/vulhub/ and is not a `*legacy*` or `*boundar*`
    script (those show that an old or unlicensed target stays out of reach, not that a block works);
  - the ID is written on a checked ("- [x]") Covered Targets row of docs/development/vulhub-coverage.md
    that names the script;
  - the script has the three assertions below, each as `echo "<message>" >&2` followed by `exit 1`.
    The patterns read the wording the Vulhub scripts share; they show that the script asserts the
    two halves and the event, not that the script passes:
      baseline   "baseline ... did not (create|execute|return|reach|connect|write) ...": the unprotected
                 container is exploited;
      protected  "protected ... (despite|still|was not blocked|executed|created) ...": the protected
                 container, given the same request, does not show the effect;
      event      "missing ... block ...", after a grep for `"action":"block"`: the agent logged
                 the block.

Usage:
  python3 deploy/shirudo/fixes_check.py              # list each entry with the line of each assertion
  python3 deploy/shirudo/fixes_check.py --check      # exit non-zero on any problem (gen-readmes.py --check does too)
  python3 deploy/shirudo/fixes_check.py --scripts    # "<ID><TAB><script under java-agent/>" per script, for replay-fixes.sh
"""
from __future__ import annotations

import datetime
import importlib.util
import pathlib
import re
import sys
import tomllib
from dataclasses import dataclass

SHIRUDO_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SHIRUDO_DIR.parent.parent
sys.path.insert(0, str(REPO_ROOT / "java-agent" / "scripts"))
import acceptance_scripts  # noqa: E402

FIXES_FILE = SHIRUDO_DIR / "fixes.toml"
BEEFILE = SHIRUDO_DIR / "ohmyrasp" / "Beefile"
PER_LINE_PACKAGES = ("ohmyrasp-java8", "ohmyrasp-java11", "ohmyrasp-java17", "ohmyrasp-jdk21", "ohmyrasp-jdk25")

MAX_FIXES = 16  # shirudo's limit per upatch
ID_FORM = re.compile(r"[A-Za-z0-9._:-]{1,255}")
NOT_EVIDENCE = acceptance_scripts.BOUNDARY
REPLAY_ARTIFACTS = ("ohmyrasp-agent-all.jar", "ohmyrasp.jar")
SCRIPT_ROOT = "acceptance/vulhub/"

FATAL = re.compile(r'^\s*echo\s+"(?P<msg>[^"]*)"\s*>&2\s*$')
BASELINE = re.compile(r"\bbaseline\b[^\"]*?\bdid not (?:create|execute|return|reach|connect|write)\b", re.I)
PROTECTED = re.compile(r"\bprotected\b[^\"]*?\b(?:despite|still|was not blocked|executed|created)\b", re.I)
EVENT = re.compile(r"\bmissing\b[^\"]*\bblock\b", re.I)
BLOCK_GREP = re.compile(r'grep\b.*"action":"block"')


@dataclass(frozen=True)
class Entry:
    id: str
    scripts: tuple[str, ...]  # relative to java-agent/
    replayed: str = ""        # ISO date of the last replay-fixes.sh run
    replayed_with: str = ""   # the JAR it ran against


@dataclass(frozen=True)
class Evidence:
    baseline: int  # 1-based line numbers in the script
    protected: int
    event: int
    block_grep: int


def load() -> list[Entry]:
    data = tomllib.loads(FIXES_FILE.read_text(encoding="utf-8"))
    return [Entry(item["id"], tuple(item.get("scripts", ())), item.get("replayed", ""), item.get("replayed_with", ""))
            for item in data.get("fix", [])]


def _check_docs():
    """scripts/check-docs.py, which owns what a ledger row is and which scripts are tracked."""
    spec = importlib.util.spec_from_file_location("check_docs_for_fixes", REPO_ROOT / "scripts" / "check-docs.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evidence(text: str) -> tuple[Evidence | None, list[str]]:
    """The line of each assertion in a script, or None and what is missing."""
    lines = text.split("\n")
    found: dict[str, int] = {}
    for no, line in enumerate(lines, start=1):
        match = FATAL.match(line)
        if not match or not any(l.strip() == "exit 1" for l in lines[no : no + 2]):
            continue
        for name, pattern in (("baseline", BASELINE), ("protected", PROTECTED), ("event", EVENT)):
            if name not in found and pattern.search(match["msg"]):
                found[name] = no
    missing = [name for name in ("baseline", "protected", "event") if name not in found]
    grep = next((no for no, line in enumerate(lines, start=1)
                 if BLOCK_GREP.search(line) and no < found.get("event", 0)), 0)
    if not grep and "event" in found:
        missing.append('a grep for "action":"block" before the event assertion')
    if missing:
        return None, missing
    return Evidence(found["baseline"], found["protected"], found["event"], grep), []


def entry_problems(entry: Entry, rows: list[str], docs) -> tuple[list[str], dict[str, Evidence]]:
    problems: list[str] = []
    found: dict[str, Evidence] = {}
    if not ID_FORM.fullmatch(entry.id):
        problems.append(f"{entry.id!r}: not a valid shirudo advisory ID (letters, digits, . _ : - ; 1 to 255 bytes)")
    if not entry.scripts:
        problems.append(f"{entry.id}: no acceptance script")
    try:
        replayed = datetime.date.fromisoformat(entry.replayed)
        if replayed > datetime.date.today():
            problems.append(f"{entry.id}: replayed = {entry.replayed!r} is in the future")
    except ValueError:
        problems.append(f"{entry.id}: `replayed` must be the ISO date (YYYY-MM-DD) of the last replay-fixes.sh run, "
                        f"got {entry.replayed!r}")
    if entry.replayed_with not in REPLAY_ARTIFACTS:
        problems.append(f"{entry.id}: `replayed_with` must be one of {', '.join(REPLAY_ARTIFACTS)}, "
                        f"got {entry.replayed_with!r}")
    id_pattern = re.compile(rf"(?<![A-Za-z0-9-]){re.escape(entry.id)}(?![A-Za-z0-9-])")
    for script in entry.scripts:
        where = f"{entry.id} / {script}"
        text = docs.script_text(script)
        if text is None:
            problems.append(f"{where}: not a tracked script under java-agent/acceptance/")
            continue
        if not script.startswith(SCRIPT_ROOT) or NOT_EVIDENCE.search(script):
            problems.append(f"{where}: must be a Vulhub script under {SCRIPT_ROOT} that is not a legacy or boundary script")
            continue
        if not any(id_pattern.search(row) and script in {path for _, path in docs.script_mentions(docs.VULHUB_LEDGER, row)}
                   for row in rows):
            problems.append(f"{where}: no checked Covered Targets row of {docs.VULHUB_LEDGER} names both")
        proof, missing = evidence(text)
        if proof is None:
            problems.append(f"{where}: the script lacks " + "; ".join(missing))
        else:
            found[script] = proof
    return problems, found


def check(compare_beefile: bool = True) -> tuple[list[str], dict[str, dict[str, Evidence]]]:
    """Problems with fixes.toml, the Beefiles and the entries, and the evidence found per entry.

    gen-readmes.py passes compare_beefile=False: it reports a Beefile that differs as a stale file."""
    problems: list[str] = []
    evidence_by_id: dict[str, dict[str, Evidence]] = {}
    entries = load()
    if not entries:
        return [f"{FIXES_FILE.name}: no [[fix]] entries"], {}
    if len(entries) > MAX_FIXES:
        problems.append(f"{FIXES_FILE.name}: {len(entries)} entries; shirudo accepts at most {MAX_FIXES} IDs in `fixes`")
    ids = [entry.id for entry in entries]
    for dupe in sorted({i for i in ids if ids.count(i) > 1}):
        problems.append(f"{FIXES_FILE.name}: {dupe} is listed more than once")
    docs = _check_docs()
    rows = docs.covered_rows(docs.read(docs.VULHUB_LEDGER))
    for entry in entries:
        found, proofs = entry_problems(entry, rows, docs)
        problems.extend(found)
        evidence_by_id[entry.id] = proofs
    problems.extend(beefile_problems(compare_beefile))
    return problems, evidence_by_id


def fixes_line(entries: list[Entry] | None = None) -> str:
    entries = load() if entries is None else entries
    return "fixes = [" + ", ".join(f'"{entry.id}"' for entry in entries) + "]"


def render_beefile(text: str) -> str:
    """The universal package's Beefile with its `fixes` line written from fixes.toml."""
    line = fixes_line()
    lines = text.split("\n")
    at = [i for i, l in enumerate(lines) if re.match(r"fixes\s*=", l)]
    if at:
        lines[at[0]] = line
        return "\n".join(l for i, l in enumerate(lines) if i not in at[1:])  # a second `fixes` is dropped
    tree = next((i for i, l in enumerate(lines) if l.strip() == "[upatches.tree]"), None)
    if tree is None:
        raise SystemExit(f"{BEEFILE}: no [upatches.tree] table to put `fixes` in")
    last = next((i for i in range(tree + 1, len(lines)) if lines[i].startswith("id")), tree)
    return "\n".join([*lines[: last + 1], line, *lines[last + 1 :]])


def beefile_problems(compare: bool = True) -> list[str]:
    problems = []
    current = BEEFILE.read_text(encoding="utf-8")
    if compare and current != render_beefile(current):
        problems.append(f"{BEEFILE.relative_to(REPO_ROOT)}: its `fixes` line differs from {FIXES_FILE.name}"
                        " (python3 deploy/shirudo/gen-readmes.py writes it)")
    for pkg in PER_LINE_PACKAGES:
        text = (SHIRUDO_DIR / pkg / "Beefile").read_text(encoding="utf-8")
        if re.search(r"^\s*fixes\s*=", text, re.M):
            problems.append(f"deploy/shirudo/{pkg}/Beefile: a per-line package carries no `fixes`")
    return problems


def main() -> int:
    if "--scripts" in sys.argv[1:]:
        for entry in load():
            for script in entry.scripts:
                print(f"{entry.id}\t{script}")
        return 0
    check_only = "--check" in sys.argv[1:]
    problems, proofs = check()
    if not check_only:
        for entry in load():
            for script, proof in proofs.get(entry.id, {}).items():
                print(f"{entry.id:15} {script}: baseline L{proof.baseline}, protected L{proof.protected},"
                      f" block grep L{proof.block_grep}, event L{proof.event}")
    for problem in problems:
        print(f"FIXES: {problem}", file=sys.stderr)
    if check_only and not problems:
        print(f"OK fixes: {len(load())} advisories, each backed by its script")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
