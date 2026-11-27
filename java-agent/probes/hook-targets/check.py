#!/usr/bin/env python3
"""Compare the library methods the packaged agent hooks, on real library versions, with the recorded hook map.

Every class of every staged library JAR goes through the line's own transformers and the methods that
come out calling the agent are compared with recorded/<family>.txt (see HookMap.java for what counts).
What the map cannot show, because the transformers run without a class loader that resolves anything
and without classBeingRedefined: the JDBC hook for an already-loaded statement implementation that
inherits a JDBC interface (the hook that keys on the loaded class, not its bytes), and any behaviour
that depends on a loader other than a plain application one, such as an OSGi framework loader.
Faking either would put the checker's classpath into the result, so the map says nothing about them.

Then the run-time hook-miss report (docs/agent.md): HookMissCheck.java runs the same transformers with the
report on over the library classes the agent's expectation table names, and the classes it reports must be
exactly those the recorded map shows the unit not hooking on that version, less what hook-miss.toml exempts.
Such a gap is itself a failure until hook-miss.toml explains it or the hook is fixed, and an entry there that no
recorded version needs fails too.

Last, HookVerify.java has this JVM verify what the transformers write (see its class comment for the details): every
library class a unit rewrites (on the primary, the whole registry, the shared visitors and each module alone; on a
backport, each transformer of the chain in registration order), and the classes of BodyReadShapes.java, read
methods of shapes the request-body hook must keep valid. Each class is defined in a fresh loader over its own JAR,
with the other staged JARs and the --verify-dependency JARs as fallback, and linked without being initialised. The
rule for a class whose dependencies are not all staged: the original class is linked too, with the same classpath.
If the original links, any error the rewritten class throws is a failure. If the original does not link (a class it
needs is missing, or its class file is newer than this JVM), the class is skipped and counted under that reason,
unless the rewritten class throws a VerifyError or ClassFormatError, which a missing class never causes. The
counts per unit (rewritten, verified, failed, skipped) are printed so that a reader sees how much the check covers.
"""
import argparse
import difflib
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import agent_track  # noqa: E402
import hookmap  # noqa: E402

UPDATE = {"primary": "java-agent/scripts/check-agent.sh --line jdk25 hook-targets --update",
          "backport": "java-agent/scripts/check-agent.sh --line java8,java11,java17 hook-targets --update"}
MAX_DIFF_LINES = 120
# JARs that only resolve classes the rewritten library classes need and the staged tree lacks, so that HookVerify
# can verify them: Undertow's servlet streams need XNIO and undertow-core, Jetty 9.4's HttpInput needs jetty-io and jetty-http.
# Staged by `run.py stage` from probe.toml (one fixture each); the digest pins the download.
VERIFY_DEPENDENCIES = {
    "io.undertow:undertow-core:2.2.39.Final": "483343864cfb270c49ba692ff0304c34dcf49328c08ba478e79a3eed063ec3b3",
    "org.eclipse.jetty:jetty-http:9.4.57.v20241219": "02c6514977f0051dfdecf8d0799acf7a88fd8008a5fd9320a92f2e5db45d297b",
    "org.eclipse.jetty:jetty-io:9.4.57.v20241219": "f6246a2cf0abcee7f0971217c0ce4cd30d8ce15a91530363457113907ab38690",
    "org.jboss.xnio:xnio-api:3.8.16.Final": "3572098fe1687dabd90f0222080fb158f63ca771c42ef1d39974434849f78bc4",
}


def staged_problems(libs: Path, libraries) -> list[str]:
    """The staged tree must hold exactly the JARs libraries.toml lists, one folder per group/artifact/version."""
    expected = {f"{lib.group}/{lib.artifact}/{version}" for lib in libraries for version in lib.versions}
    staged = set()
    for jar in libs.glob("*/*/*/*.jar"):
        staged.add("/".join(jar.relative_to(libs).parts[:3]))
    problems = [f"not staged: {name}" for name in sorted(expected - staged)]
    problems += [f"staged but not in libraries.toml: {name}" for name in sorted(staged - expected)]
    return problems


def download_dependency(coordinate: str, target: Path):
    """Stage one VERIFY_DEPENDENCIES JAR from Maven Central."""
    if coordinate not in VERIFY_DEPENDENCIES:
        raise SystemExit(f"{coordinate} is not one of the pinned VERIFY_DEPENDENCIES of check.py")
    group, artifact, version = coordinate.split(":")
    url = f"https://repo.maven.apache.org/maven2/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar"
    with urllib.request.urlopen(url, timeout=45) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != VERIFY_DEPENDENCIES[coordinate]:
        raise SystemExit(f"{coordinate}: digest mismatch for {url}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def verify(classes: str, agent: Path, libs: Path, entry: str, dependencies: list[Path]) -> list[str]:
    """Run HookVerify in a JVM of its own; print its counts and return its failures."""
    start = time.monotonic()
    run = subprocess.run(["java", "-Xmx3g", "-cp", os.pathsep.join((classes, str(agent))), "HookVerify", str(agent), str(libs), entry,
                          *map(str, dependencies)], capture_output=True, text=True, timeout=900)
    sys.stderr.write(run.stderr)
    if run.returncode:
        raise SystemExit(f"HookVerify failed:\n{run.stdout[-2000:]}\n{run.stderr[-4000:]}")
    failures = []
    for line in run.stdout.splitlines():
        if line.startswith("fail\t"):
            unit, library, version, cls, message = line.split("\t", 5)[1:]
            failures.append(f"{unit} rewrote {cls} of {library} {version} into a class this JVM rejects: {message}")
        else:
            print(line)
    print(f"rewritten classes verified by this JVM in {time.monotonic() - start:.1f}s")
    return failures


def generate(agent: Path, libs: Path, track: str, misses: bool, dependencies: list[Path]) -> tuple[str, str, list[str]]:
    """The hook map, (unless `misses` is false) the hook-miss harness's output, both with {N} for a backport's token,
    and the classes the JVM rejects."""
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="hook-targets-") as tmp:
        subprocess.run(["javac", "-cp", str(agent), "-d", tmp, str(here / "HookMap.java"), str(here / "HookMapSelfCheck.java"),
                        str(here / "HookMissCheck.java"), str(here / "HookVerify.java"), str(here / "BodyReadShapes.java")], check=True)
        # The rules the map is counted by, on classes made for the purpose, before they are applied to real ones.
        subprocess.run(["java", "-cp", os.pathsep.join((tmp, str(agent))), "HookMapSelfCheck"], check=True, timeout=120)
        # A JAR may hold several lines; name the one under test by its entry class.
        entry = "primary" if track == "main" else f"io/ohmyrasp/agent/java{track}/OhMyRaspJava{track}Agent"
        run = subprocess.run(["java", "-Xmx3g", "-cp", os.pathsep.join((tmp, str(agent))), "HookMap", str(agent), str(libs), entry],
                             capture_output=True, text=True, timeout=900)
        sys.stderr.write(run.stderr)
        if run.returncode:
            raise SystemExit(f"HookMap failed:\n{run.stdout[-2000:]}\n{run.stderr[-4000:]}")
        miss = None
        if misses:
            miss = subprocess.run(["java", "-Xmx2g", "-cp", os.pathsep.join((tmp, str(agent))), "HookMissCheck", str(agent), str(libs), entry],
                                  capture_output=True, text=True, timeout=900)
            sys.stderr.write(miss.stderr)
            if miss.returncode:
                raise SystemExit(f"HookMissCheck failed:\n{miss.stdout[-2000:]}\n{miss.stderr[-4000:]}")
        rejected = verify(tmp, agent, libs, entry, dependencies)
    return hookmap.normalise(run.stdout, track), hookmap.normalise(miss.stdout, track) if miss else "", rejected


def hook_miss_problems(agent: Path, libs: Path, family: str, hook_map, run_output: str) -> list[str]:
    """The run-time report against the recorded map: the same pairs, none unexplained, no entry of hook-miss.toml unused."""
    hook_miss = hookmap.load_hook_miss()
    problems = hookmap.hook_miss_entry_problems({family: hook_map}, hook_miss)
    table_entry = f"META-INF/ohmyrasp/hook-expectations/{family}.txt"
    with zipfile.ZipFile(agent) as jar:
        shipped = jar.read(table_entry).decode() if table_entry in jar.namelist() else None
    if shipped != hookmap.expectation_table(family, hook_map, hook_miss):
        return problems + [f"the agent JAR's {table_entry} is not the table of recorded/{family}.txt and hook-miss.toml: "
                           "run `python3 java-agent/scripts/gen-hook-targets.py` and rebuild the agent"]
    claims, reports = hookmap.parse_miss_run(run_output)
    expected, exempted = hookmap.derived_misses(claims, hook_map, hook_miss)
    reported = {report[:4] for report in reports}
    for unit, cls, library, version in sorted(reported - expected):
        problems.append(f"the run-time report names {unit} on {cls} of {library} {version}, which the recorded map shows hooked")
    for unit, cls, library, version in sorted(expected - reported):
        problems.append(f"the run-time report misses {unit} on {cls} of {library} {version}, which the recorded map shows not hooked")
    for unit, cls, library, version in sorted(expected & reported):
        problems.append(f"{unit} hooks {cls} on other versions but not on {library} {version}: fix the hook, or explain the gap "
                        "in probes/hook-targets/hook-miss.toml")
    jars = {}
    for jar in libs.glob("*/*/*/*.jar"):
        group, artifact, version = jar.relative_to(libs).parts[:3]
        with zipfile.ZipFile(jar) as archive:
            jars[(f"{group}:{artifact}", version)] = {hookmap.runtime_class(n[:-6]) for n in archive.namelist() if n.endswith(".class")}
    hooked = {(unit, hookmap.runtime_class(row.cls), row.library, row.version) for row in hookmap.named_rows(hook_map) for unit in row.units}
    for (unit, cls), pair in sorted(hook_miss.items()):
        if hookmap.family_of(unit) != family:
            continue
        needed = ((unit, cls) in exempted if pair.check == "absent"
                  else any(cls in classes and (unit, cls, library, version) not in hooked for (library, version), classes in jars.items()))
        if not needed:
            problems.append(f"hook-miss.toml: no recorded version needs the {pair.check} entry for {unit} on {cls}; remove it")
    print(f"{family}: hook-miss report checked on {len(claims)} claimed (unit, class, version) triples; "
          f"{len(reports)} reported, {len(exempted)} pairs exempted by hook-miss.toml")
    return problems


def write_update(path: Path, text: str):
    """Write the recorded map, or hand it to check-agent.sh, which copies PROBE_UPDATE_ROOT back into java-agent/."""
    root = os.environ.get("PROBE_UPDATE_ROOT")
    target = Path(root) / path.relative_to(hookmap.HERE.parent.parent) if root else path
    if target.exists() and root and target.read_text() != text:
        raise SystemExit(f"{path.name}: the agent lines of one family produce different maps; fix that before recording")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    print(f"recorded {path.relative_to(hookmap.HERE.parent.parent)}" + (" (copied back by check-agent.sh)" if root else ""))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path, nargs="?")
    parser.add_argument("--libs", type=Path, help="staged library tree (:stageHookTargets)")
    parser.add_argument("--verify-dependency", type=Path, action="append", default=[],
                        help="a JAR that only resolves classes for HookVerify (a VERIFY_DEPENDENCIES fixture)")
    parser.add_argument("--download-dependency", nargs=2, metavar=("COORDINATE", "PATH"),
                        help="stage one VERIFY_DEPENDENCIES JAR (run.py stage does this)")
    parser.add_argument("--update", action="store_true", help="record the map this agent produces instead of comparing")
    args = parser.parse_args()
    if args.download_dependency:
        if args.agent or args.libs:
            parser.error("--download-dependency stages a JAR as a separate operation")
        download_dependency(args.download_dependency[0], Path(args.download_dependency[1]))
        return
    if not args.agent or not args.libs:
        parser.error("provide the agent JAR and --libs")
    agent = args.agent.resolve(strict=True)
    track = agent_track.track(agent) or "main"
    family = "primary" if track == "main" else "backport"
    libraries = hookmap.load_libraries()
    problems = staged_problems(args.libs, libraries)
    if problems:
        raise SystemExit("staged libraries differ from libraries.toml (run :stageHookTargets):\n  " + "\n  ".join(problems))

    dependencies = [path.resolve(strict=True) for path in args.verify_dependency]
    map_text, miss_text, rejected = generate(agent, args.libs, track, not args.update, dependencies)
    produced = hookmap.banner(family, UPDATE[family]) + map_text
    recorded_path = hookmap.RECORDED / f"{family}.txt"
    if args.update:
        write_update(recorded_path, produced)
        recorded = produced
    else:
        recorded = recorded_path.read_text() if recorded_path.exists() else ""
        if recorded != produced:
            diff = list(difflib.unified_diff(recorded.splitlines(), produced.splitlines(),
                                             f"recorded/{family}.txt", f"{family} agent now", lineterm="", n=1))
            shown = "\n".join(diff[:MAX_DIFF_LINES]) + (f"\n... {len(diff) - MAX_DIFF_LINES} more diff lines" if len(diff) > MAX_DIFF_LINES else "")
            raise SystemExit(f"The hooks this agent applies to the library versions changed:\n{shown}\n\n"
                             f"If the change is intended, record it with `{UPDATE[family]}` and review the diff of "
                             f"java-agent/probes/hook-targets/recorded/{family}.txt."
                             + "".join(f"\n\nAlso, {failure}" for failure in rejected))

    # The guards read this run's map for its own family and the committed one for the other family. A
    # first `--update` has no committed map for the other family yet: that update runs the lines of both.
    maps = {family: hookmap.parse(recorded)}
    for other in hookmap.FAMILIES:
        if other != family:
            candidates = [hookmap.RECORDED / f"{other}.txt"]
            if os.environ.get("PROBE_UPDATE_ROOT"):
                candidates.insert(0, Path(os.environ["PROBE_UPDATE_ROOT"]) / candidates[0].relative_to(hookmap.HERE.parent.parent))
            found = next((c for c in candidates if c.exists()), None)
            if found:
                maps[other] = hookmap.parse(found.read_text())
            elif args.update:
                print(f"no recorded {other} map yet: guards need it, so they run after `--update` has recorded both families")
            else:
                raise SystemExit(f"recorded/{other}.txt is missing")
    problems = hookmap.check_units({f: m for f, m in maps.items()}, {f: a for f, a in hookmap.load_allowlist().items() if f in maps})
    if len(maps) == len(hookmap.FAMILIES):
        problems += hookmap.check_library_versions(libraries, maps)
    if args.update:
        print("hook-miss report not checked while recording: run `python3 java-agent/scripts/gen-hook-targets.py`, "
              "rebuild, and run the probe again without --update")
    else:
        problems += hook_miss_problems(agent, args.libs, family, maps[family], miss_text)
    problems += rejected
    if problems:
        raise SystemExit("hook coverage guards failed:\n  " + "\n  ".join(problems))
    named = hookmap.named_rows(maps[family])
    print(f"{family}: {len(named)} hook rows on named targets, "
          f"{len(maps[family].rows) - len(named)} call-site rewrites; {maps[family].stats}")


if __name__ == "__main__":
    main()
