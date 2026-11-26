"""Guards for scripts/gates.py: the gate table must keep describing what CI runs.

Run: python3 -m unittest discover -s scripts -p 'test_gates.py'
"""
import re
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

    def test_workflows_run_when_only_the_contract_examples_change(self):
        # agent.yml filters on java-agent/**; daemon.yml needs the examples listed because they live there.
        fixture = "java-agent/contracts/agent-daemon/control/mode-block.json"
        for name, patterns in (("agent.yml", ("java-agent/**",)), ("daemon.yml", ("java-agent/contracts/**",))):
            text = (WORKFLOWS / name).read_text()
            for event in ("push", "pull_request"):
                block = re.search(rf"^  {event}:\n((?:    .*\n)+)", text, re.M).group(1)
                for pattern in patterns:
                    self.assertIn(f'- "{pattern}"', block, f"{name} {event} paths must include {pattern} ({fixture})")

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

    def test_changed_paths_pick_the_expected_gates(self):
        def ids(paths, slow=False):
            return [gate.id for gate, _ in gates.select(paths, slow)]
        self.assertEqual(ids(["README.md"]), ["docs"])
        self.assertEqual(ids(["daemon/src/main.rs"]), ["docs", "daemon"])
        self.assertEqual(ids(["java-agent/agent-java11/src/main/java/X.java"]), ["docs", "agent-parity", "agent-backports"])
        self.assertEqual(ids(["java-agent/shared/src/main/java/X.java"]), ["docs", "agent-primary", "agent-backports"])
        self.assertIn("agent-probes", ids(["java-agent/shared/src/main/java/X.java"], slow=True))
        # The agent-daemon contract examples are read by the agent tests on every line and by the daemon tests.
        self.assertEqual(ids(["java-agent/contracts/agent-daemon/control/mode-block.json"]),
                         ["docs", "agent-primary", "agent-backports", "daemon"])
        self.assertEqual(ids(["java-agent/probes/file-read/check.py"]), ["docs", "probe-registry", "probe:file-read"])
        # The library list and the recorded hook maps are inputs of the hook-targets probe and of a generated doc.
        for path in ("java-agent/probes/hook-targets/libraries.toml", "java-agent/probes/hook-targets/recorded/primary.txt"):
            self.assertEqual(ids([path]), ["docs", "probe-registry", "probe:hook-targets"])


if __name__ == "__main__":
    unittest.main()
