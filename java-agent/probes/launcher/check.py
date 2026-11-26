#!/usr/bin/env python3
"""Check that the launcher starts the line that fits this JDK, skips JARs that do not fit, starts one line per JVM and never stops the JVM."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(COMMON))
import agent_track  # noqa: E402

LAUNCHER = "io/ohmyrasp/agent/launch/AgentLauncher.class"
ENTRY_CLASSES = {
    agent_track.PRIMARY: "io.ohmyrasp.agent.OhMyRaspAgent",
    "17": "io.ohmyrasp.agent.java17.OhMyRaspJava17Agent",
    "11": "io.ohmyrasp.agent.java11.OhMyRaspJava11Agent",
    "8": "io.ohmyrasp.agent.java8.OhMyRaspJava8Agent",
}
AGENT_OPTIONS = ["-Dohmyrasp.standalone=true", "-Dohmyrasp.mode=block", "-Dohmyrasp.control=none",
                 "-Dohmyrasp.log=stderr", "-Dohmyrasp.log.sync=true"]
FAILURE_MESSAGE = "simulated by the launcher probe"


class Run:
    def __init__(self, name, options, agents, app_args, classes):
        command = ["java", *options, *(f"-javaagent:{agent}" for agent in agents),
                   "-cp", str(classes), "LauncherCheck", *app_args]
        process = subprocess.run(command, capture_output=True, text=True, timeout=120)
        self.name, self.code, self.out, self.err = name, process.returncode, process.stdout, process.stderr
        output = (self.out + self.err).splitlines()
        self.launcher = [json.loads(line) for line in output if line.startswith('{"event":"ohmyrasp-agent-')]
        self.starts = [track for line in output for track in (start_track(line),) if track]

    def fail(self, why):
        raise SystemExit(f"{self.name}: {why}\nexit {self.code}\n--- stdout\n{self.out}--- stderr\n{self.err}")

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
        print(f"ok   {self.name}")


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
    """A JAR holding the real launcher and an entry for `track` whose premain throws a LinkageError."""
    package, _, name = ENTRY_CLASSES[track].rpartition(".")
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
                         "Premain-Class: io.ohmyrasp.agent.launch.AgentLauncher\n\n")
        fixture.writestr(LAUNCHER, source_jar.read(LAUNCHER))
        entry = ENTRY_CLASSES[track].replace(".", "/") + ".class"
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

    major = agent_track.java_major()
    expected = agent_track.launcher_choice(set(agent_track.LINE_NAMES), major)
    if expected is None:
        raise SystemExit(f"no agent line fits Java {major}; the probes cover 8, 11, 17, 21 and 25")
    if agent_track.tracks_in(universal) != set(agent_track.LINE_NAMES):
        raise SystemExit(f"{universal.name} does not hold every line: {sorted(agent_track.tracks_in(universal))}")
    track_arg = [expected]
    skipped = ("ohmyrasp-agent-skipped", "unsupported-java")
    active = ("ohmyrasp-agent-skipped", "already-active")
    print(f"Java {major}: the launcher should start {agent_track.LINE_NAMES[expected]}")

    with tempfile.TemporaryDirectory(prefix="launcher-") as tmp:
        work = Path(tmp)
        classes = work / "classes"
        classes.mkdir()
        subprocess.run(["javac", "-d", str(classes), str(COMMON / "HttpTransportCheck.java"),
                        str(Path(__file__).with_name("LauncherCheck.java"))], check=True)

        Run("universal JAR starts the fitting line and blocks", AGENT_OPTIONS, [universal], track_arg, classes) \
            .expect([expected], True, [])

        unfit = []
        for jar in line_jars:
            held = agent_track.tracks_in(jar)
            if len(held) != 1:
                raise SystemExit(f"{jar.name} should hold one line, holds {sorted(held)}")
            if agent_track.launcher_choice(held, major) is not None:
                continue
            unfit.append(jar)
            run = Run(f"{jar.name} does not fit Java {major} and is skipped", AGENT_OPTIONS, [jar], [], classes)
            run.expect([], None, [skipped])
            line = run.launcher[0]
            if line["lines"] != agent_track.LINE_NAMES[next(iter(held))] or str(major) not in line["java_version"]:
                run.fail(f"unexpected skip details {line}")

        for order in ([agent, universal], [universal, agent]):
            names = " + ".join(jar.name for jar in order)
            run = Run(f"{names}: one line starts", AGENT_OPTIONS, order, track_arg, classes)
            run.expect([expected], True, [active])
            if run.launcher[0]["active_line"] != agent_track.LINE_NAMES[expected]:
                run.fail(f"unexpected active line {run.launcher[0]}")

        if unfit:
            # The JVM loads a Premain-Class by name, so the second JAR's premain runs the first JAR's
            # launcher; a JAR that does not fit must not keep the one that does from starting. Java 8
            # puts every agent JAR on the class path before the first premain, so the first launcher
            # already sees and starts the fitting line. Java 9 and later add each JAR just before its
            # own premain, so the first launcher finds no fitting line and the second starts it.
            Run(f"{unfit[0].name} before the universal JAR: the fitting line still starts", AGENT_OPTIONS,
                [unfit[0], universal], track_arg, classes).expect([expected], True, [active if major == 8 else skipped])

        run = Run("a line whose premain throws does not stop the JVM", AGENT_OPTIONS,
                  [failing_entry_jar(universal, expected, work)], [], classes)
        run.expect([], None, [("ohmyrasp-agent-start-failed", None)])
        line = run.launcher[0]
        if (line["line"], line["exception"], line["message"]) != (
                agent_track.LINE_NAMES[expected], "java.lang.NoClassDefFoundError", FAILURE_MESSAGE):
            run.fail(f"unexpected failure details {line}")

        # The baked properties (standalone, log=stderr, mode=block, lock_config=true) are read from the
        # universal JAR by the line that starts. With lock_config, the monitor flag below is ignored, so
        # the read is blocked only when the line found the one properties file in this JAR. The general
        # JAR, which has no properties file, shows that the flag alone does let the read through.
        monitor = [option for option in AGENT_OPTIONS if not option.startswith("-Dohmyrasp.mode=")]
        Run("the monitor flag lets the read through without baked properties", [*monitor, "-Dohmyrasp.mode=monitor"],
            [universal], track_arg, classes).expect([expected], False, [])
        Run("universal shirudo JAR applies its baked properties", ["-Dohmyrasp.mode=monitor"], [shirudo],
            track_arg, classes).expect([expected], True, [])
    print(f"{len(unfit)} per-line JAR(s) do not fit Java {major} and were skipped")


if __name__ == "__main__":
    main()
