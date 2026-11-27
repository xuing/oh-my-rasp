#!/usr/bin/env python3
"""Find invokedynamic call sites in the packaged agent JARs and gate the backport lines.

Why: the agent JAR sits on the bootstrap class path and its hook methods run inside
JDK classes (FileInputStream, URL, ProcessImpl, Base64$Decoder, ...). An invokedynamic
call site (a lambda or method reference, a record's toString/equals/hashCode, a
pattern-matching switch, string concatenation compiled with --release 9 or later) is
linked on its first execution. Linking loads and spins classes and can read files, which
can re-enter the hooked API or fail during early startup. Plain `var`, text blocks, switch
expressions over strings or enums and instanceof patterns compile without invokedynamic.

  check-dynamic-calls.py                 every call site: line, class, method, bootstrap method
  check-dynamic-calls.py --summary       counts per line and bootstrap kind, top classes
  check-dynamic-calls.py --check         fail when a backport line has a site its baseline does not record
  check-dynamic-calls.py --update        rewrite dynamic-calls.baseline.json from the JARs

The JARs are the ones java-agent/probes/lines.toml names; build them first (see
CONTRIBUTING.md). Standard library only; no JDK needed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASELINE = HERE / "dynamic-calls.baseline.json"
SHADED_PREFIX = "io/ohmyrasp/agent/shaded/"
LINES = ("java8", "java11", "java17", "jdk25")  # lines.toml ids recorded in the baseline

LAMBDA, CONCAT, RECORD, SWITCH, OTHER = "lambda", "string-concat", "record", "switch", "other"
KINDS = (LAMBDA, CONCAT, RECORD, SWITCH, OTHER)
# Every kind is gated on the backport lines, string concatenation too: their own sources compile with
# -XDstringConcat=inline, and their baseline records no site at all.
GATED_KINDS = KINDS
BOOTSTRAP_KIND = {
    "java/lang/invoke/LambdaMetafactory": LAMBDA,
    "java/lang/invoke/StringConcatFactory": CONCAT,
    "java/lang/runtime/ObjectMethods": RECORD,
    "java/lang/runtime/SwitchBootstraps": SWITCH,
}
KIND_WORDS = {
    LAMBDA: "a lambda or method reference",
    RECORD: "a record's generated toString/equals/hashCode",
    SWITCH: "a pattern-matching or enum-class switch (SwitchBootstraps)",
    OTHER: "an invokedynamic or dynamic constant with a bootstrap method of its own",
    CONCAT: "string concatenation (StringConcatFactory)",
}

# Fixed instruction lengths by opcode; tableswitch, lookupswitch and wide are handled apart.
_LENGTH = {op: 1 for op in range(0xCA)}
_LENGTH.update({0x10: 2, 0x11: 3, 0x12: 2, 0x13: 3, 0x14: 3, 0x84: 3, 0xA9: 2, 0xBC: 2, 0xC5: 4,
                0xB9: 5, 0xBA: 5, 0xC8: 5, 0xC9: 5})
_LENGTH.update({op: 2 for op in (*range(0x15, 0x1A), *range(0x36, 0x3B))})
_LENGTH.update({op: 3 for op in (*range(0x99, 0xA9), *range(0xB2, 0xB9), 0xBB, 0xBD, 0xC0, 0xC1, 0xC6, 0xC7)})
INVOKEDYNAMIC, LDC, LDC_W, LDC2_W, TABLESWITCH, LOOKUPSWITCH, WIDE = 0xBA, 0x12, 0x13, 0x14, 0xAA, 0xAB, 0xC4


@dataclass(frozen=True)
class Site:
    line: str
    cls: str       # internal name, e.g. io/ohmyrasp/agent/Foo
    method: str    # name + descriptor of the method that holds the call site
    bootstrap: str  # owner.name of the bootstrap method, e.g. java/lang/invoke/LambdaMetafactory.metafactory

    @property
    def kind(self) -> str:
        return BOOTSTRAP_KIND.get(self.bootstrap.rpartition(".")[0], OTHER)


class ClassFormatError(Exception):
    pass


def parse_class(data: bytes) -> tuple[str, list[tuple[str, str]]]:
    """Return (internal class name, [(method name+descriptor, 'owner.name')]) for every dynamic call site."""
    pos = 0

    def take(fmt: str):
        nonlocal pos
        size = struct.calcsize(fmt)
        if pos + size > len(data):
            raise ClassFormatError("truncated class file")
        values = struct.unpack_from(fmt, data, pos)
        pos += size
        return values if len(values) > 1 else values[0]

    if take(">I") != 0xCAFEBABE:
        raise ClassFormatError("bad magic")
    take(">HH")
    count = take(">H")
    pool: list[tuple | None] = [None] * count
    index = 1
    while index < count:
        tag = take(">B")
        if tag == 1:
            length = take(">H")
            pool[index] = (1, data[pos:pos + length].decode("utf-8", "replace"))
            pos += length
        elif tag in (3, 4):
            pos += 4
        elif tag in (5, 6):
            pos += 8
            index += 1  # long and double take two slots
        elif tag in (7, 8, 16, 19, 20):
            pool[index] = (tag, take(">H"))
        elif tag in (9, 10, 11, 12, 17, 18):
            pool[index] = (tag, *take(">HH"))
        elif tag == 15:
            pool[index] = (15, *take(">BH"))
        else:
            raise ClassFormatError(f"unknown constant pool tag {tag}")
        index += 1

    def utf8(i: int) -> str:
        return pool[i][1]

    def class_name(i: int) -> str:
        return utf8(pool[i][1])

    take(">H")  # access flags
    this_class = class_name(take(">H"))
    take(">H")
    interfaces = take(">H")
    pos += 2 * interfaces

    def read_attributes() -> list[tuple[str, int, int]]:
        nonlocal pos
        found = []
        for _ in range(take(">H")):
            name = utf8(take(">H"))
            length = take(">I")
            found.append((name, pos, length))
            pos += length
        return found

    for _ in range(take(">H")):  # fields
        take(">HHH")
        read_attributes()
    raw: list[tuple[str, int]] = []  # (method, constant pool index of the call site), resolved after the class attributes
    for _ in range(take(">H")):  # methods
        take(">H")
        method = utf8(take(">H")) + utf8(take(">H"))
        for name, start, length in read_attributes():
            if name == "Code":
                code_length = struct.unpack_from(">I", data, start + 4)[0]
                raw.extend((method, ref) for ref in _dynamic_refs(data, start + 8, code_length, pool))

    bootstraps: list[str] = []
    for name, start, length in read_attributes():
        if name == "BootstrapMethods":
            at = start + 2
            for _ in range(struct.unpack_from(">H", data, start)[0]):
                handle, nargs = struct.unpack_from(">HH", data, at)
                at += 4 + 2 * nargs
                _, _, ref = pool[handle]
                _, owner, nat = pool[ref]
                bootstraps.append(f"{class_name(owner)}.{utf8(pool[nat][1])}")
    return this_class, [(method, bootstraps[pool[ref][1]]) for method, ref in raw]


def _dynamic_refs(data: bytes, start: int, length: int, pool) -> list[int]:
    """Constant pool indexes of every invokedynamic and ldc of a CONSTANT_Dynamic in a code array."""
    refs, at, end = [], start, start + length
    while at < end:
        op = data[at]
        if op == INVOKEDYNAMIC:
            refs.append(struct.unpack_from(">H", data, at + 1)[0])
        elif op in (LDC, LDC_W, LDC2_W):
            ref = data[at + 1] if op == LDC else struct.unpack_from(">H", data, at + 1)[0]
            if pool[ref] is not None and pool[ref][0] == 17:
                refs.append(ref)
        if op == TABLESWITCH:
            base = start + ((at - start + 4) & ~3)  # padding aligns to the code array, not the file
            low, high = struct.unpack_from(">ii", data, base + 4)
            at = base + 12 + 4 * (high - low + 1)
        elif op == LOOKUPSWITCH:
            base = start + ((at - start + 4) & ~3)  # padding aligns to the code array, not the file
            at = base + 8 + 8 * struct.unpack_from(">i", data, base + 4)[0]
        elif op == WIDE:
            at += 6 if data[at + 1] == 0x84 else 4
        else:
            at += _LENGTH[op]
    return refs


def scan_jar(line: str, jar: Path) -> list[Site]:
    sites = []
    with zipfile.ZipFile(jar) as archive:
        for entry in sorted(archive.namelist()):
            # Shaded classes are scanned too: ASM runs in the transformers, inside class definition.
            if not entry.endswith(".class"):
                continue
            try:
                name, found = parse_class(archive.read(entry))
            except (ClassFormatError, IndexError, struct.error, TypeError) as error:
                raise SystemExit(f"{jar}: cannot parse {entry}: {error}") from error
            prefix = entry[:entry.rindex("/") + 1] if entry.startswith("META-INF/") else ""
            sites.extend(Site(line, prefix + name, method, bootstrap) for method, bootstrap in found)
    return sites


def summarize(sites: list[Site]) -> dict[str, dict[str, int]]:
    """{class: {kind: count}} with zero kinds left out and keys sorted."""
    table: dict[str, Counter] = defaultdict(Counter)
    for site in sites:
        table[site.cls][site.kind] += 1
    return {cls: {k: table[cls][k] for k in KINDS if table[cls][k]} for cls in sorted(table)}


def totals(table: dict[str, dict[str, int]]) -> Counter:
    result: Counter = Counter()
    for kinds in table.values():
        result.update(kinds)
    return result


def compare(baseline: dict[str, dict[str, int]], sites: list[Site]) -> list[str]:
    """One message per class whose gated site count grew past the baseline (or is new)."""
    current = summarize(sites)
    messages = []
    for cls, kinds in current.items():
        grown = [k for k in GATED_KINDS if kinds.get(k, 0) > baseline.get(cls, {}).get(k, 0)]
        for kind in grown:
            allowed = baseline.get(cls, {}).get(kind, 0)
            where = sorted({s.method for s in sites if s.cls == cls and s.kind == kind})
            messages.append(
                f"{sites[0].line}: {cls} has {kinds[kind]} call site(s) of {KIND_WORDS[kind]}, "
                f"the baseline allows {allowed}"
                + (" (the class is not in the baseline)" if cls not in baseline else "")
                + "\n    in method(s): " + "; ".join(where)
                + ("" if cls not in baseline else
                   "\n    (the baseline counts per class, so the new site may be any of these)"))
    return messages


FIX = """\
A call site like this is linked the first time it runs. Linking loads and generates classes and can
read files, which can re-enter a hooked JDK API or fail during early startup, and this agent's
hook methods run inside those APIs. Instead:
  - use an anonymous class or a static nested class for a lambda or method reference;
  - write equals/hashCode/toString by hand instead of a record or pattern-matching switch;
  - use if/else on instanceof where a pattern-matching switch was meant;
  - compile string concatenation with -XDstringConcat=inline (the backport modules do).
The backport lines allow no call site at all, shaded classes included: the rule is in this script, and
--update does not record one."""


def load_lines():
    spec = importlib.util.spec_from_file_location("ohmyrasp_probe_runner", HERE.parent / "probes" / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolves string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


def jar_paths(java_agent: Path, build_root: Path | None) -> dict[str, tuple[str, Path]]:
    runner = load_lines()
    lines = runner.load_lines()
    missing = [name for name in LINES if name not in lines]
    if missing:
        raise SystemExit(f"lines.toml has no line {', '.join(missing)}")
    resolved = {}
    for name in LINES:
        path = runner.locate(lines[name].jar, build_root)
        if build_root is None and java_agent != runner.JAVA_AGENT:
            path = java_agent / lines[name].jar
        resolved[name] = (lines[name].family, path)
    return resolved


def read_baseline(path: Path) -> dict[str, dict[str, dict[str, int]]]:
    return json.loads(path.read_text())["lines"]


def write_baseline(path: Path, lines: dict[str, dict[str, dict[str, int]]]) -> None:
    document = {
        "comment": "Generated by java-agent/scripts/check-dynamic-calls.py --update. Invokedynamic call sites "
                   "per agent line, per class, per bootstrap kind. Counts, not line numbers. Do not hand-edit.",
        "lines": lines,
    }
    path.write_text(json.dumps(document, indent=1, sort_keys=False) + "\n")


def print_summary(line: str, sites: list[Site], top: int = 5) -> None:
    table = summarize(sites)
    count = totals(table)
    print(f"{line}: {sum(count.values())} sites in {len(table)} classes; "
          + ", ".join(f"{k}={count[k]}" for k in KINDS))
    ranked = sorted(table.items(), key=lambda item: (-sum(item[1].values()), item[0]))[:top]
    for cls, kinds in ranked:
        print(f"    {sum(kinds.values()):4d}  {cls}  " + " ".join(f"{k}={n}" for k, n in kinds.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("java_agent", nargs="?", type=Path, default=HERE.parent,
                        help="the java-agent directory (default: this script's parent's parent)")
    parser.add_argument("--build-root", type=Path,
                        help="Gradle build root when build directories are redirected (as for probes/run.py)")
    parser.add_argument("--baseline", type=Path, default=BASELINE, help=argparse.SUPPRESS)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="fail when a backport line gained a gated call site")
    mode.add_argument("--update", action="store_true", help="rewrite the baseline from the JARs")
    mode.add_argument("--summary", action="store_true", help="counts per line and kind, and the top classes")
    parser.add_argument("--line", help="comma-separated lines to read instead of all of them (not with --update)")
    args = parser.parse_args(argv)

    java_agent = args.java_agent.resolve()
    jars = jar_paths(java_agent, args.build_root)
    if args.line:
        wanted = args.line.split(",")
        if args.update or any(line not in jars for line in wanted):
            parser.error(f"--line takes any of {', '.join(jars)} and cannot be combined with --update")
        jars = {line: jars[line] for line in wanted}
    absent = [str(path) for _, path in jars.values() if not path.is_file()]
    if absent:
        print("missing JAR(s), build them first (see CONTRIBUTING.md, `gradle :agent-java8:agentJava8Jar ...`):\n  "
              + "\n  ".join(absent), file=sys.stderr)
        return 2
    scanned = {line: scan_jar(line, path) for line, (_, path) in jars.items()}

    if args.update:
        recorded = {line: summarize(sites) for line, sites in scanned.items()}
        refused = [line for line, (family, _) in jars.items() if family == "backport" and recorded[line]]
        if refused:
            # Zero is the rule for the backport lines, not a number of the baseline.
            for line in refused:
                print_summary(line, scanned[line])
            print(f"\nnot written: {', '.join(refused)} hold invokedynamic call sites, and the backport lines "
                  "allow none\n\n" + FIX, file=sys.stderr)
            return 1
        write_baseline(args.baseline, recorded)
        for line, sites in scanned.items():
            print_summary(line, sites)
        print(f"wrote {args.baseline}")
        return 0
    if args.summary:
        for line, sites in scanned.items():
            print_summary(line, sites)
        return 0
    if not args.check:
        for sites in scanned.values():
            for site in sites:
                print(f"{site.line}\t{site.cls}\t{site.method}\t{site.bootstrap}")
        return 0

    baseline = read_baseline(args.baseline)
    failures = []
    for line, (family, _) in jars.items():
        count = totals(summarize(scanned[line]))
        if family != "backport":
            print(f"{line}: primary line, recorded but not gated ({sum(count.values())} sites)")
            continue
        found = compare({}, scanned[line])  # none allowed, whatever the baseline file says
        failures.extend(found)
        print(f"{line}: {'FAIL' if found else 'ok'}; sites "
              + ", ".join(f"{k}={count[k]}" for k in GATED_KINDS))
    if failures:
        print("\ninvokedynamic check failed:\n", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        print("\n" + FIX, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
