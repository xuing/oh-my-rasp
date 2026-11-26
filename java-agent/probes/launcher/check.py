#!/usr/bin/env python3
"""Check that each agent JAR starts the line that fits this JDK, skips when none fits, starts one line per JVM and never stops the JVM."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(COMMON))
import agent_track  # noqa: E402

LAUNCH = "io/ohmyrasp/agent/launch/"
LINE_ENTRIES = {
    agent_track.PRIMARY: "io.ohmyrasp.agent.OhMyRaspAgent",
    "17": "io.ohmyrasp.agent.java17.OhMyRaspJava17Agent",
    "11": "io.ohmyrasp.agent.java11.OhMyRaspJava11Agent",
    "8": "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent",
}
AGENT_OPTIONS = ["-Dohmyrasp.standalone=true", "-Dohmyrasp.mode=block", "-Dohmyrasp.control=none",
                 "-Dohmyrasp.log=stderr", "-Dohmyrasp.log.sync=true"]
MONITOR_OPTIONS = [o for o in AGENT_OPTIONS if not o.startswith("-Dohmyrasp.mode=")] + ["-Dohmyrasp.mode=monitor"]
FAILURE_MESSAGE = "simulated by the launcher probe"
SKIPPED = ("ohmyrasp-agent-skipped", "unsupported-java")
ACTIVE = ("ohmyrasp-agent-skipped", "already-active")
EARLIER_FAILED = ("ohmyrasp-agent-skipped", "earlier-start-failed")
FAILED = ("ohmyrasp-agent-start-failed", None)
# One line of -verbose:class per class definition: "[Loaded X from Y]" on Java 8, "... X source: Y" later.
LAUNCHER_LOAD = re.compile(r"(?:\[Loaded |\] )io\.ohmyrasp\.agent\.launch\.AgentLauncher(?: from | source: )(.*?)\]?$")


class Probe:
    def __init__(self, work, major):
        self.work, self.major, self.passed = work, major, 0
        self.classes = work / "classes"
        self.classes.mkdir()
        subprocess.run(["javac", "-d", str(self.classes), str(COMMON / "HttpTransportCheck.java"),
                        str(Path(__file__).with_name("LauncherCheck.java"))], check=True)
        tools = Path(shutil.which("java")).resolve().parent.parent / "lib" / "tools.jar"  # the attach API on JDK 8
        self.classpath = [str(self.classes), *([str(tools)] if tools.is_file() else [])]

    def run(self, name, options, agents, app_args, extra_classpath=()):
        # With more than one of our JARs in the JVM, show where the shared launcher class was defined.
        several = len(agents) + (len(app_args) - 2 if "attach" in app_args else 0) > 1
        command = ["java", "-Djdk.attach.allowAttachSelf=true", *(["-verbose:class"] if several else []), *options,
                   *(f"-javaagent:{agent}" for agent in agents),
                   "-cp", os.pathsep.join([*self.classpath, *map(str, extra_classpath)]), "LauncherCheck", *app_args]
        return Run(self, name, command, subprocess.run(command, capture_output=True, text=True, timeout=120))

    def fits(self, jar):
        return agent_track.launcher_choice(agent_track.tracks_in(jar), self.major)

    def first_fit(self, agents):
        """The track the first attached JAR with a fitting line starts."""
        return next((track for track in map(self.fits, agents) if track), None)


class Run:
    def __init__(self, probe, name, command, process):
        self.probe, self.name, self.command = probe, name, command
        self.code, self.out, self.err = process.returncode, process.stdout, process.stderr
        output = (self.out + self.err).splitlines()
        self.launcher = [json.loads(line) for line in output if line.startswith('{"event":"ohmyrasp-agent-')]
        self.starts = [track for track in map(start_track, output) if track]
        self.launcher_sources = [m[1] for m in map(LAUNCHER_LOAD.search, output) if m]
        published = [line.split("=", 1)[1] for line in output if line.startswith("launcher-check: published line=")]
        self.published = published[0] if published else None

    def fail(self, why):
        out = "\n".join(line for line in self.out.splitlines()
                        if "[class,load]" not in line and not line.startswith("[Loaded "))
        raise SystemExit(f"{self.name}: {why}\nexit {self.code}\n--- stdout (class loading omitted)\n{out}\n"
                         f"--- stderr\n{self.err}")

    def expect(self, started, blocked, launcher_lines):
        if self.code != 0:
            self.fail("the JVM did not exit 0")
        if "launcher-check: application ran" not in self.out:
            self.fail("the application did not run")
        if self.starts != started:
            self.fail(f"expected starts {started}, saw {self.starts}")
        if blocked is not None and f"launcher-check: blocked={str(blocked).lower()}" not in self.out:
            self.fail(f"expected blocked={blocked}")
        reasons = [(line["event"], line.get("reason")) for line in self.launcher]
        if reasons != launcher_lines:
            self.fail(f"expected launcher lines {launcher_lines}, saw {reasons}")
        if started and self.published != agent_track.LINE_NAMES[started[0]]:
            self.fail(f"ohmyrasp.agent.line is {self.published}, expected {agent_track.LINE_NAMES[started[0]]}")
        self.probe.passed += 1
        # Informational: a JVM can define AgentLauncher more than once (a line appends its JAR to the
        # bootstrap search); the launcher reads every definition's state, so one line still starts.
        source = (f" (AgentLauncher from {', '.join(Path(s).name for s in self.launcher_sources)})"
                  if self.launcher_sources else "")
        print(f"ok   {self.name}{source}")
        return self


def start_track(line):
    """The track whose own start output this line is, or None."""
    if line.startswith("[OHMYRASP] agent started with ASM transformer"):
        return agent_track.PRIMARY
    if line.startswith('{"event":"ohmyrasp-java'):
        event = json.loads(line)["event"]
        for track in ("8", "11", "17"):
            if event == f"ohmyrasp-java{track}-agent-start":
                return track
    return None


def failing_entry_jar(universal, track, work):
    """The real launcher and universal entry, with a line entry for `track` whose premain throws."""
    package, _, name = LINE_ENTRIES[track].rpartition(".")
    source = work / "failing" / (name + ".java")
    source.parent.mkdir()
    source.write_text(f"package {package};\n"
                      f"public final class {name} {{\n"
                      "  public static void premain(String args, java.lang.instrument.Instrumentation inst) {\n"
                      f'    throw new NoClassDefFoundError("{FAILURE_MESSAGE}");\n'
                      "  }\n}\n")
    classes = work / "failing-classes"
    classes.mkdir()
    subprocess.run(["javac", "-d", str(classes), str(source)], check=True)
    jar = work / "failing-entry.jar"
    with zipfile.ZipFile(universal) as source_jar, zipfile.ZipFile(jar, "w") as fixture:
        fixture.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n"
                         f"Premain-Class: {LAUNCH.replace('/', '.')}UniversalEntry\n\n")
        for launcher_class in ("AgentLauncher.class", "UniversalEntry.class"):
            fixture.writestr(LAUNCH + launcher_class, source_jar.read(LAUNCH + launcher_class))
        entry = LINE_ENTRIES[track].replace(".", "/") + ".class"
        fixture.write(classes / entry, entry)
    return jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path, help="the line's JAR, or the universal JAR")
    parser.add_argument("--all-jar", type=Path, required=True, help="the universal agent JAR")
    parser.add_argument("--shirudo-jar", type=Path, required=True, help="the universal shirudo upatch JAR")
    parser.add_argument("--line-jar", type=Path, action="append", required=True, help="a per-line agent JAR")
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    universal = args.all_jar.resolve(strict=True)
    shirudo = args.shirudo_jar.resolve(strict=True)
    line_jars = [jar.resolve(strict=True) for jar in args.line_jar]
    tested = agent_track.track(agent) or agent_track.PRIMARY  # the line the registry says is under test

    major = agent_track.java_major()
    if agent_track.tracks_in(universal) != set(agent_track.LINE_NAMES):
        raise SystemExit(f"{universal.name} does not hold every line: {sorted(agent_track.tracks_in(universal))}")
    with tempfile.TemporaryDirectory(prefix="launcher-") as tmp:
        work = Path(tmp)
        probe = Probe(work, major)
        expected = probe.fits(universal)
        if expected is None:
            raise SystemExit(f"no agent line fits Java {major}; the probes cover 8, 11, 17, 21 and 25")
        print(f"Java {major}: the universal JAR should start {agent_track.LINE_NAMES[expected]}, "
              f"the JAR under test {agent_track.LINE_NAMES[tested]}")

        probe.run(f"{agent.name} starts the line under test and blocks", AGENT_OPTIONS, [agent], [tested]) \
            .expect([tested], True, [])
        probe.run("the universal JAR starts the fitting line and blocks", AGENT_OPTIONS, [universal], [expected]) \
            .expect([expected], True, [])

        unfit = [jar for jar in line_jars if probe.fits(jar) is None]
        for jar in unfit:
            run = probe.run(f"{jar.name} does not fit Java {major} and is skipped", AGENT_OPTIONS, [jar], [])
            run.expect([], None, [SKIPPED])
            line = run.launcher[0]
            held = agent_track.LINE_NAMES[next(iter(agent_track.tracks_in(jar)))]
            if (line["lines"], line["jar"]) != (held, jar.name) or str(major) not in line["java_version"]:
                run.fail(f"unexpected skip details {line}")
        for jar in unfit:
            for second in dict.fromkeys([agent, universal]):
                probe.run(f"{jar.name} first, {second.name} second: the second starts", AGENT_OPTIONS,
                          [jar, second], [probe.fits(second)]).expect([probe.fits(second)], True, [SKIPPED])

        preset = ["-Dohmyrasp.agent.state=installed:primary", "-Dohmyrasp.agent.line=primary"]
        for jar in dict.fromkeys([agent, universal]):
            probe.run(f"{jar.name} starts although the command line presets the state properties",
                      [*AGENT_OPTIONS, *preset], [jar], [probe.fits(jar)]).expect([probe.fits(jar)], True, [])

        fitting = [jar for jar in line_jars if jar not in unfit]
        orders = [[agent, agent], [universal, universal]]
        orders += [order for jar in dict.fromkeys([agent, *fitting]) for order in ([jar, universal], [universal, jar])]
        for order in dict.fromkeys(tuple(order) for order in orders):
            started = probe.first_fit(order)
            run = probe.run(f"{order[0].name} + {order[1].name}: one line starts", AGENT_OPTIONS, order, [started])
            run.expect([started], True, [ACTIVE])
            if run.launcher[0]["state"] != f"installed:{agent_track.LINE_NAMES[started]}":
                run.fail(f"unexpected state {run.launcher[0]}")

        java8 = next(jar for jar in line_jars if agent_track.tracks_in(jar) == {"8"})
        if major > 8:
            # The Java 8 JAR's Boot-Class-Path puts the Java 8 line on the bootstrap loader even when the
            # launcher skips it. Started by hand there, the line cannot see java.sql: it must fail before it
            # registers a transformer, so no transformer class of the line is ever loaded.
            linker = work / "link-failure.jar"
            subprocess.run(["javac", "-d", str(work / "link-classes"), str(Path(__file__).with_name("LinkFailureAgent.java"))],
                           check=True)
            with zipfile.ZipFile(linker, "w") as fixture:
                fixture.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nPremain-Class: LinkFailureAgent\n"
                                 "Can-Retransform-Classes: true\n\n")  # as every agent JAR declares
                fixture.write(work / "link-classes" / "LinkFailureAgent.class", "LinkFailureAgent.class")
            run = probe.run("a backport line that cannot link a type fails before installing a transformer",
                            AGENT_OPTIONS, [java8, linker], ["none"])
            for wanted in ("link-check: line loader=null", "link-check: failed java.lang.NoClassDefFoundError: java/sql/",
                           "link-check: transformer classes loaded=0"):
                if wanted not in run.out:
                    run.fail(f"expected '{wanted}'")
            run.expect([], None, [SKIPPED])

        failing = failing_entry_jar(universal, expected, work)
        run = probe.run("a line whose premain throws does not stop the JVM", AGENT_OPTIONS, [failing], [])
        run.expect([], None, [FAILED])
        line = run.launcher[0]
        if (line["line"], line["exception"], line["message"], line["protection"]) != (
                agent_track.LINE_NAMES[expected], "java.lang.NoClassDefFoundError", FAILURE_MESSAGE,
                "inactive or incomplete"):
            run.fail(f"unexpected failure details {line}")
        probe.run("after a failed start, a later JAR starts no line", AGENT_OPTIONS, [failing, universal], []) \
            .expect([], None, [FAILED, EARLIER_FAILED])

        probe.run("agentmain alone starts the fitting line", AGENT_OPTIONS, [], [expected, "attach", str(universal)]) \
            .expect([expected], True, [])
        probe.run("two racing attaches start one line", AGENT_OPTIONS, [],
                  [expected, "attach", str(universal), str(universal)]).expect([expected], True, [ACTIVE])
        probe.run("agentmain after premain starts nothing", AGENT_OPTIONS, [universal],
                  [expected, "attach", str(universal)]).expect([expected], True, [ACTIVE])
        # A line appends its JAR to the bootstrap search, and the Java 8 JAR's Boot-Class-Path puts its
        # entry there too, so this attach reaches a second, bootstrap definition of AgentLauncher. The
        # one-start state must be the same object for both definitions.
        probe.run("the Java 8 JAR attached after the universal JAR's premain starts nothing", AGENT_OPTIONS,
                  [universal], [expected, "attach", str(java8)]).expect([expected], True, [ACTIVE])

        # Baked properties (standalone, log=stderr, mode=block, lock_config=true) are read from the JAR the
        # started line's entry class came from. With lock_config the monitor flag is ignored, so the read
        # is blocked only when the line read ohmyrasp.jar's file; the general JAR shows the flag works.
        probe.run("the monitor flag lets the read through without baked properties", MONITOR_OPTIONS,
                  [universal], [expected]).expect([expected], False, [])
        probe.run("ohmyrasp.jar applies its baked properties", ["-Dohmyrasp.mode=monitor"], [shirudo],
                  [expected]).expect([expected], True, [])
        decoy = work / "decoy"
        (decoy / "META-INF").mkdir(parents=True)
        (decoy / "META-INF" / "ohmyrasp-shirudo.properties").write_text(
            "standalone=true\nlock_config=false\nmode=monitor\ncontrol=none\nlog=stderr\nlatency_sample=0\n")
        probe.run("a same-named properties file on the application class path does not override ohmyrasp.jar's",
                  [], [shirudo], [expected], extra_classpath=[decoy]).expect([expected], True, [])
        probe.run("ohmyrasp.jar first, the general universal JAR second: ohmyrasp.jar's properties apply",
                  ["-Dohmyrasp.mode=monitor"], [shirudo, universal], [expected]).expect([expected], True, [ACTIVE])
        # The line entry class loads by name through the system class loader, from the first attached JAR
        # that holds it, so the general JAR attached first starts the line without baked properties.
        probe.run("the general universal JAR first: it starts, without ohmyrasp.jar's properties", MONITOR_OPTIONS,
                  [universal, shirudo], [expected]).expect([expected], False, [ACTIVE])
    print(f"{probe.passed} launcher cases passed on Java {major}; {len(unfit)} per-line JAR(s) do not fit it")


if __name__ == "__main__":
    main()
