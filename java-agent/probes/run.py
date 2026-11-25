#!/usr/bin/env python3
"""Run packaged-agent probes against an agent line.

A probe is a directory here with a check.py that takes an agent JAR and exits
non-zero when the packaged agent decides differently from what the probe
expects. probe.toml, when present, says what else the probe needs and where it
does not apply. lines.toml lists the agent lines (JAR x JDK runtime).

  run.py list                         probes and the lines each one runs on
  run.py plan  --line jdk25 [probe..] the exact commands `run` would execute
  run.py run   --line java8 [probe..] run them with the java/javac on PATH
  run.py stage                        download fixtures that probes fetch themselves
  run.py gradle-tasks --line java8,jdk25 [probe..]
                                      Gradle tasks that build the JARs and stage fixtures

With no probe named, every probe that applies to the line runs. Arguments after
`--` go to the probe (one probe only). CI and java-agent/scripts/check-agent.sh
both call this file, so a probe added here needs no other registration.
"""
from __future__ import annotations

import argparse
import ast
import os
import re
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
JAVA_AGENT = HERE.parent
ROOT_PROJECT = "ohmyrasp"  # rootProject.name in settings.gradle.kts; names the root build dir under --build-root
NOT_PROBES = {"common", "__pycache__"}


@dataclass(frozen=True)
class Line:
    id: str
    family: str
    jdk: str
    jar: str
    tests: str
    build: tuple[str, ...]
    upatch: str | None = None


@dataclass(frozen=True)
class Fixture:
    flag: str
    path: str
    gradle: str | None = None       # Gradle task that stages it
    stage: tuple[str, ...] = ()     # or: check.py arguments that download it ({path} is substituted)


@dataclass(frozen=True)
class Probe:
    id: str
    summary: str
    fixtures: tuple[Fixture, ...] = ()
    family: str | None = None       # run only on this family
    lines: tuple[str, ...] = ()     # or only on these lines
    why: str = ""                   # reason for the restriction
    manual: str = ""                # never selected automatically; the text says what it needs
    isolated: bool = False          # must run without network, hostname localhost
    windows: bool = False           # also runs natively on Windows in CI
    script: Path = field(default=Path(), compare=False)

    def skip_reason(self, line: Line) -> str | None:
        if self.manual:
            return f"manual: {self.manual}"
        if self.family and self.family != line.family:
            return f"{self.family} lines only: {self.why}"
        if self.lines and line.id not in self.lines:
            return f"{', '.join(self.lines)} only: {self.why}"
        return None


def load_lines() -> dict[str, Line]:
    rows = tomllib.loads((HERE / "lines.toml").read_text())["line"]
    return {row["id"]: Line(**{**row, "build": tuple(row["build"])}) for row in rows}


def load_probes() -> dict[str, Probe]:
    probes = {}
    for directory in sorted(p for p in HERE.iterdir() if p.is_dir() and p.name not in NOT_PROBES):
        script = directory / "check.py"
        if not script.is_file():
            sys.exit(f"{directory.relative_to(JAVA_AGENT)} has no check.py; every directory here is a probe")
        summary = (ast.get_docstring(ast.parse(script.read_text())) or "").splitlines()[0]
        manifest = directory / "probe.toml"
        data = tomllib.loads(manifest.read_text()) if manifest.is_file() else {}
        applies = data.pop("applies", {})
        fixtures = tuple(Fixture(**{**f, "stage": tuple(f.get("stage", ()))}) for f in data.pop("fixture", ()))
        probes[directory.name] = Probe(
            id=directory.name, summary=summary, fixtures=fixtures, script=script,
            family=applies.get("family"), lines=tuple(applies.get("lines", ())), why=applies.get("why", ""),
            **data)
    return probes


def locate(path: str, build_root: Path | None) -> Path:
    """Resolve a java-agent-relative build path, optionally under a redirected Gradle build root."""
    if build_root is not None:
        project, separator, rest = path.partition("build/")
        if separator:
            return build_root / (project.rstrip("/") or ROOT_PROJECT) / rest
    return JAVA_AGENT / path


def command(probe: Probe, line: Line, args) -> list[str]:
    jar = args.jar or locate(line.jar, args.build_root)
    fixtures = [part for f in probe.fixtures for part in (f.flag, str(locate(f.path, args.build_root)))]
    return [sys.executable, str(probe.script), str(jar), *fixtures, *args.probe_args]


def select(probes: dict[str, Probe], line: Line, args) -> tuple[list[Probe], list[tuple[Probe, str]]]:
    named = [probes[name] for name in args.probes] if args.probes else list(probes.values())
    chosen, skipped = [], []
    for probe in named:
        reason = probe.skip_reason(line)
        if args.windows and not probe.windows:
            continue
        if args.probes and probe.manual:
            reason = None  # naming a manual probe is the opt-in
        if reason is None and probe.isolated != args.isolated and not args.plan_only:
            reason = ("needs --isolated: run it with no network and hostname localhost" if probe.isolated
                      else "not an isolated probe")
        if reason is None:
            chosen.append(probe)
        else:
            skipped.append((probe, reason))
    return chosen, skipped


def java_major() -> str:
    text = subprocess.run(["java", "-version"], capture_output=True, text=True, check=True).stderr
    version = re.search(r'version "([^"]+)"', text).group(1)
    return version.split(".")[1] if version.startswith("1.") else version.split(".")[0]


def cmd_list(probes, lines, args):
    width = max(map(len, probes))
    for probe in probes.values():
        on = [line.id for line in lines.values() if probe.skip_reason(line) is None]
        scope = "all lines" if len(on) == len(lines) else (", ".join(on) or "manual")
        tags = "".join(f" [{t}]" for t in ("isolated", "windows") if getattr(probe, t))
        print(f"{probe.id:{width}}  {scope:32}  {probe.summary}{tags}")
        restriction = probe.manual or probe.why
        if restriction:
            print(f"{'':{width}}  {'':32}  why: {restriction}")


def cmd_plan(probes, lines, args):
    line = lines[args.line]
    args.plan_only = True
    chosen, skipped = select(probes, line, args)
    for probe in chosen:
        print(" ".join(["python3", *(os.path.relpath(part, JAVA_AGENT) if part.startswith("/") else part
                                    for part in command(probe, line, args)[1:])]))
    for probe, reason in skipped:
        print(f"# skip {probe.id}: {reason}")


def cmd_run(probes, lines, args):
    line = lines[args.line]
    if not args.any_jdk and java_major() != line.jdk:
        sys.exit(f"line {line.id} runs on JDK {line.jdk}, but `java` on PATH is JDK {java_major()}. "
                 "A pass on another runtime says nothing about this line. Use --any-jdk to override.")
    chosen, skipped = select(probes, line, args)
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    failed = []
    for probe in chosen:
        missing = [f.path for f in probe.fixtures if not locate(f.path, args.build_root).exists()]
        if missing:
            print(f"FAIL {line.id} {probe.id}: fixture not staged: {', '.join(missing)} "
                  f"(see `run.py gradle-tasks` and `run.py stage`)", flush=True)
            failed.append(probe.id)
            continue
        if in_actions:
            print(f"::group::{probe.id}: {probe.summary}", flush=True)
        start = time.monotonic()
        code = subprocess.run(command(probe, line, args)).returncode
        if in_actions:
            print("::endgroup::", flush=True)
        print(f"{'ok  ' if code == 0 else 'FAIL'} {line.id} {probe.id} {time.monotonic() - start:.1f}s", flush=True)
        if code:
            failed.append(probe.id)
            if not args.keep_going:
                break
    for probe, reason in skipped:
        print(f"skip {line.id} {probe.id}: {reason}")
    if args.report:
        ran = {p.id: ("fail" if p.id in failed else "pass") for p in chosen}
        rows = [(p.id, ran.get(p.id, "skipped")) for p in probes.values() if p.id in ran or any(p is s for s, _ in skipped)]
        args.report.write_text("".join(f"{line.id}\t{name}\t{status}\n" for name, status in rows))
    if failed:
        sys.exit(f"{len(failed)} probe(s) failed on {line.id}: {', '.join(failed)}")
    print(f"{len(chosen)} probe(s) passed on {line.id}")


def cmd_stage(probes, lines, args):
    for probe in probes.values():
        for fixture in probe.fixtures:
            target = locate(fixture.path, args.build_root)
            if fixture.stage and not target.exists():
                subprocess.run([sys.executable, str(probe.script),
                                *(part.replace("{path}", str(target)) for part in fixture.stage)], check=True)
                print(f"staged {fixture.path} ({probe.id})")


def cmd_gradle_tasks(probes, lines, args):
    tasks = []
    for line_id in args.line.split(","):
        line = lines[line_id]
        tasks += [*line.build, *(f.gradle for p in select(probes, line, args)[0] for f in p.fixtures if f.gradle)]
    print(" ".join(dict.fromkeys(tasks)))


def main():
    argv = sys.argv[1:]
    probe_args = []
    if "--" in argv:
        probe_args = argv[argv.index("--") + 1:]
        argv = argv[:argv.index("--")]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    commands = {"list": cmd_list, "plan": cmd_plan, "run": cmd_run, "stage": cmd_stage, "gradle-tasks": cmd_gradle_tasks}
    for name in commands:
        p = sub.add_parser(name)
        p.add_argument("--build-root", type=Path, help="Gradle build root when build directories are redirected "
                       "(<root>/<project>/..., as java-agent/scripts/check-agent.sh does)")
        if name in ("plan", "run", "gradle-tasks"):
            p.add_argument("--line", required=True)
            p.add_argument("probes", nargs="*")
            p.add_argument("--isolated", action="store_true", help="select the probes that need a network-less run")
            p.add_argument("--windows", action="store_true", help="select only the probes that also run on Windows")
        if name in ("plan", "run"):
            p.add_argument("--jar", type=Path, help="agent JAR to use instead of the line's own")
        if name == "run":
            p.add_argument("--keep-going", action="store_true", help="run the remaining probes after a failure")
            p.add_argument("--any-jdk", action="store_true", help="do not require the line's JDK on PATH")
            p.add_argument("--report", type=Path, help="write line, probe, status as TSV")
    args = parser.parse_args(argv)
    args.probe_args = probe_args
    args.plan_only = args.action == "gradle-tasks"
    lines, probes = load_lines(), load_probes()
    for name in getattr(args, "probes", []):
        if name not in probes:
            parser.error(f"unknown probe {name}; `run.py list` shows them")
    if probe_args and len(getattr(args, "probes", [])) != 1:
        parser.error("arguments after -- need exactly one probe")
    if hasattr(args, "line"):
        for line_id in args.line.split(","):
            if line_id not in lines:
                parser.error(f"unknown line {line_id}; lines.toml has {', '.join(lines)}")
    commands[args.action](probes, lines, args)


if __name__ == "__main__":
    main()
