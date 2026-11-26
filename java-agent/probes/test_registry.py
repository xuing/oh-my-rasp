"""Guards for the probe registry: what CI and the build must agree on with lines.toml and probe.toml.

Run: python3 -m unittest discover -s java-agent/probes -p 'test_*.py'
"""
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
JAVA_AGENT = HERE.parent
WORKFLOWS = JAVA_AGENT.parent / ".github" / "workflows"

sys.path.insert(0, str(HERE))
import run as runner  # noqa: E402


class RegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = runner.load_lines()
        cls.probes = runner.load_probes()
        cls.gradle = "\n".join(p.read_text() for p in JAVA_AGENT.glob("**/build.gradle.kts") if "/build/" not in p.as_posix())

    def test_registry_is_not_empty(self):
        # A scan that silently finds nothing would make every other check here pass.
        self.assertGreaterEqual(len(self.probes), 20)
        self.assertGreaterEqual(len(self.lines), 6)

    def test_every_probe_says_what_it_checks(self):
        for probe in self.probes.values():
            self.assertTrue(probe.summary, f"{probe.id}/check.py needs a module docstring; it is the probe's description")

    def test_every_restriction_gives_a_reason(self):
        for probe in self.probes.values():
            if probe.family or probe.lines:
                self.assertTrue(probe.why, f"{probe.id}/probe.toml restricts lines without [applies] why")
            for line in probe.lines:
                self.assertIn(line, self.lines, f"{probe.id}/probe.toml names an unknown line")
            if probe.family:
                self.assertIn(probe.family, {line.family for line in self.lines.values()})

    def test_every_staged_fixture_names_how_it_is_staged(self):
        for probe in self.probes.values():
            for fixture in probe.fixtures:
                self.assertTrue(bool(fixture.gradle) != bool(fixture.stage),
                                f"{probe.id}: fixture {fixture.path} needs exactly one of gradle or stage")
                if fixture.gradle:
                    task = fixture.gradle.rsplit(":", 1)[-1]
                    self.assertIn(f'"{task}"', self.gradle, f"{probe.id}: Gradle task {fixture.gradle} is not registered")

    def test_line_tasks_exist_in_the_build(self):
        for line in self.lines.values():
            for task in line.build:
                module, name = task.strip(":").split(":")
                self.assertIn(f'"{name}"', (JAVA_AGENT / module / "build.gradle.kts").read_text(), f"{line.id}: {task}")

    def test_ci_matrix_is_the_lines_table(self):
        job = (WORKFLOWS / "agent.yml").read_text()
        job = job[job.index("  runtime-compatibility:"):]
        rows = re.findall(r'- line: (\S+)\n\s+java: "(\d+)"\n\s+jar: (\S+)(?:\n\s+upatch: (\S+))?', job)
        self.assertEqual({(line, jdk, jar, upatch or None) for line, jdk, jar, upatch in rows},
                         {(line.id, line.jdk, line.jar, line.upatch) for line in self.lines.values()},
                         "the runtime-compatibility matrix in agent.yml and probes/lines.toml differ")

    def test_universal_jar_is_built_and_uploaded(self):
        jar, build = runner.load_universal()
        for task in build:
            module, name = task.strip(":").split(":")
            self.assertIn(f'"{name}"', (JAVA_AGENT / module / "build.gradle.kts").read_text(), task)
        self.assertIn(f"java-agent/{jar}", (WORKFLOWS / "agent.yml").read_text(),
                      "the runtime matrix downloads the universal JAR from the build job's artifact")

    def test_ci_runs_every_row_against_the_universal_jar(self):
        job = (WORKFLOWS / "agent.yml").read_text()
        job = job[job.index("  runtime-compatibility:"):]
        self.assertIn('run.py run --line "${{ matrix.line }}" --keep-going', job)
        self.assertIn('run.py run --line "${{ matrix.line }}" --artifact all --keep-going', job)

    def test_artifact_all_runs_the_family_the_launcher_starts(self):
        jar, build = runner.load_universal()
        for line in self.lines.values():
            universal = runner.for_artifact(line, "all")
            self.assertIs(runner.for_artifact(line, "line"), line)
            if line.id == "java17-on-21":
                # The launcher starts the primary line on JDK 21; the jdk21 line runs those probes.
                self.assertIsNone(universal)
                continue
            self.assertEqual((universal.jar, universal.build, universal.family, universal.jdk),
                             (jar, build, line.family, line.jdk), line.id)
        covered = {(line.jdk, line.family) for line in self.lines.values() if runner.for_artifact(line, "all")}
        self.assertEqual(covered, {(line.jdk, runner.universal_family(line.jdk)) for line in self.lines.values()},
                         "every JDK in lines.toml gets one universal pass, on the family its launcher starts")

    def test_artifact_all_substitutes_the_universal_jar_in_commands(self):
        args = runner.argparse.Namespace(jar=None, build_root=None, probe_args=[])
        probe = self.probes["background-process"]
        universal = runner.for_artifact(self.lines["java8"], "all")
        self.assertEqual(runner.command(probe, universal, args)[2],
                         str(JAVA_AGENT / runner.load_universal()[0]))

    def test_ci_runs_probes_through_the_registry(self):
        # A workflow that names a probe's check.py has a second list to forget.
        for workflow in WORKFLOWS.glob("*.yml"):
            named = re.findall(r"probes/([a-z0-9-]+)/check\.py", workflow.read_text())
            self.assertEqual(named, [], f"{workflow.name} calls probes directly; use probes/run.py")


if __name__ == "__main__":
    unittest.main()
