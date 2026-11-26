#!/usr/bin/env python3
"""Compare the library methods the packaged agent hooks, on real library versions, with the recorded hook map.

Every class of every staged library JAR goes through the line's own transformers and the methods that
come out calling the agent are compared with recorded/<family>.txt (see HookMap.java for what counts).
What the map cannot show, because the transformers run without a class loader that resolves anything
and without classBeingRedefined: the JDBC hook for an already-loaded statement implementation that
inherits a JDBC interface (the hook that keys on the loaded class, not its bytes), and any behaviour
that depends on a loader other than a plain application one, such as an OSGi framework loader.
Faking either would put the checker's classpath into the result, so the map says nothing about them.
"""
import argparse
import difflib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
import agent_track  # noqa: E402
import hookmap  # noqa: E402

UPDATE = {"primary": "java-agent/scripts/check-agent.sh --line jdk25 hook-targets --update",
          "backport": "java-agent/scripts/check-agent.sh --line java8,java11,java17 hook-targets --update"}
MAX_DIFF_LINES = 120


def staged_problems(libs: Path, libraries) -> list[str]:
    """The staged tree must hold exactly the JARs libraries.toml lists, one folder per group/artifact/version."""
    expected = {f"{lib.group}/{lib.artifact}/{version}" for lib in libraries for version in lib.versions}
    staged = set()
    for jar in libs.glob("*/*/*/*.jar"):
        staged.add("/".join(jar.relative_to(libs).parts[:3]))
    problems = [f"not staged: {name}" for name in sorted(expected - staged)]
    problems += [f"staged but not in libraries.toml: {name}" for name in sorted(staged - expected)]
    return problems


def generate(agent: Path, libs: Path, track: str) -> str:
    here = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="hook-targets-") as tmp:
        subprocess.run(["javac", "-cp", str(agent), "-d", tmp, str(here / "HookMap.java"), str(here / "HookMapSelfCheck.java")], check=True)
        # The rules the map is counted by, on classes made for the purpose, before they are applied to real ones.
        subprocess.run(["java", "-cp", os.pathsep.join((tmp, str(agent))), "HookMapSelfCheck"], check=True, timeout=120)
        # A JAR may hold several lines; name the one under test by its entry class.
        entry = "primary" if track == "main" else f"io/ohmyrasp/agent/java{track}/OhMyRaspJava{track}Agent"
        run = subprocess.run(["java", "-Xmx3g", "-cp", os.pathsep.join((tmp, str(agent))), "HookMap", str(agent), str(libs), entry],
                             capture_output=True, text=True, timeout=900)
    sys.stderr.write(run.stderr)
    if run.returncode:
        raise SystemExit(f"HookMap failed:\n{run.stdout[-2000:]}\n{run.stderr[-4000:]}")
    return hookmap.normalise(run.stdout, track)


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
    parser.add_argument("agent", type=Path)
    parser.add_argument("--libs", required=True, type=Path, help="staged library tree (:stageHookTargets)")
    parser.add_argument("--update", action="store_true", help="record the map this agent produces instead of comparing")
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    track = agent_track.track(agent) or "main"
    family = "primary" if track == "main" else "backport"
    libraries = hookmap.load_libraries()
    problems = staged_problems(args.libs, libraries)
    if problems:
        raise SystemExit("staged libraries differ from libraries.toml (run :stageHookTargets):\n  " + "\n  ".join(problems))

    produced = hookmap.banner(family, UPDATE[family]) + generate(agent, args.libs, track)
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
                             f"java-agent/probes/hook-targets/recorded/{family}.txt.")

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
    if problems:
        raise SystemExit("hook coverage guards failed:\n  " + "\n  ".join(problems))
    named = hookmap.named_rows(maps[family])
    print(f"{family}: {len(named)} hook rows on named targets, "
          f"{len(maps[family].rows) - len(named)} call-site rewrites; {maps[family].stats}")


if __name__ == "__main__":
    main()
