"""Guards for scripts/gates.py: the gate table must keep describing what CI runs.

Run: python3 -m unittest discover -s scripts -p 'test_gates.py'
"""
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gates  # noqa: E402

WORKFLOWS = gates.ROOT / ".github" / "workflows"


def in_workflow(command: str, text: str) -> bool:
    """A gate command is in a workflow when its last `&&` step appears there (CI sets the directory separately)."""
    return command.split("&&")[-1].strip() in text


class GatesTest(unittest.TestCase):
    def test_every_gate_names_where_ci_runs_it(self):
        for gate in gates.GATES:
            self.assertTrue(bool(gate.ci) != bool(gate.local), f"{gate.id}: give exactly one of ci or local")
            if gate.ci:
                text = (WORKFLOWS / gate.ci).read_text()
                for command in gate.commands:
                    self.assertTrue(in_workflow(command, text),
                                    f"{gate.id}: `{command}` is not in .github/workflows/{gate.ci}; "
                                    "update the gate or the workflow so they run the same thing")

    def test_every_gate_script_exists(self):
        for gate in gates.GATES:
            for command in gate.commands:
                for word in command.replace("&&", " ").split():
                    if word.endswith((".py", ".sh")) and "/" in word:
                        base = gates.ROOT / "java-agent" if command.startswith("cd java-agent") else gates.ROOT
                        self.assertTrue((base / word).is_file(), f"{gate.id}: {word} does not exist")

    def test_every_source_directory_has_a_gate_beyond_docs(self):
        # A new top-level component with no gate would get only the docs check.
        tracked = subprocess.run(["git", "-C", str(gates.ROOT), "ls-files"], capture_output=True, text=True, check=True)
        top = {line.split("/")[0] for line in tracked.stdout.splitlines() if "/" in line}
        self.assertGreaterEqual(len(top), 6)  # the scan found the repo
        for directory in sorted(top - {"docs", ".claude"}):
            sample = next(p for p in tracked.stdout.splitlines() if p.startswith(directory + "/"))
            covered = [g.id for g in gates.GATES if g.paths and any(
                p.startswith(directory + "/") or directory + "/" == p[:len(directory) + 1] for p in g.paths)]
            self.assertTrue(covered, f"no gate lists a path under {directory}/ (for example {sample})")

    def test_probe_sweep_covers_the_line_jars_and_the_universal_jar(self):
        commands = gates.BY_ID["agent-probes"].commands
        self.assertEqual(len(commands), 2)
        self.assertNotIn("--artifact", commands[0])
        self.assertIn("--artifact all", commands[1])
        self.assertEqual(commands[0].replace("check-agent.sh ", "check-agent.sh --artifact all "), commands[1])

    def test_changed_paths_pick_the_expected_gates(self):
        def ids(paths, slow=False):
            return [gate.id for gate, _ in gates.select(paths, slow)]
        self.assertEqual(ids(["README.md"]), ["docs"])
        self.assertEqual(ids(["daemon/src/main.rs"]), ["docs", "daemon"])
        self.assertEqual(ids(["java-agent/agent-java11/src/main/java/X.java"]), ["docs", "agent-parity", "agent-backports"])
        self.assertEqual(ids(["java-agent/shared/src/main/java/X.java"]), ["docs", "agent-primary", "agent-backports"])
        self.assertIn("agent-probes", ids(["java-agent/shared/src/main/java/X.java"], slow=True))
        self.assertEqual(ids(["java-agent/probes/file-read/check.py"]), ["docs", "probe-registry", "probe:file-read"])


if __name__ == "__main__":
    unittest.main()
