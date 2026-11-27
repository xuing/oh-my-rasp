"""Unit tests for check-backport-drift.py, on small trees written to a temporary directory."""
import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_backport_drift", HERE / "check-backport-drift.py")
drift = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = drift
spec.loader.exec_module(drift)


def hooks(line: str, body: str) -> str:
    return f"package io.ohmyrasp.agent.java{line};\nfinal class Java{line}RaspHooks {{\n{body}}}\n"


class Tree:
    def __init__(self, root: Path):
        self.root = root
        (root / "scripts").mkdir()

    def write(self, line: str, relative: str, text: str) -> None:
        path = self.root / f"agent-java{line}" / relative.replace("<N>", line)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def same_everywhere(self, body: str) -> None:
        for line in ("8", "11", "17"):
            self.write(line, "build.gradle.kts", f'options.release.set({line})\n')
            self.write(line, "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java", hooks(line, body))

    def run(self, *args: str) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = drift.main(["--root", str(self.root), *args])
        return code, err.getvalue()


class DriftTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tree = Tree(Path(self.tmp.name))

    def test_version_tokens_are_not_differences(self):
        text = 'Opcodes.V1_8 "java8_command" Java8RaspHooks "Java 8" JAVA8 ohmyrasp-java8-x io/ohmyrasp/agent/java8'
        for line, opcode in (("11", "V11"), ("17", "V17")):
            other = text.replace("V1_8", opcode).replace("8", line)
            self.assertEqual(drift.normalise(text, "8"), drift.normalise(other, line))

    def test_a_longer_number_is_not_a_version_token(self):
        self.assertNotEqual(drift.normalise("java80", "8"), drift.normalise("java110", "11"))
        self.assertEqual("release.set(8)", drift.normalise("release.set(8)", "8"))

    def test_another_lines_token_is_a_difference(self):
        # agent-java11 must not carry the java17 class-file constant or a java17 name.
        self.assertNotEqual(drift.normalise("Opcodes.V1_8", "8"), drift.normalise("Opcodes.V17", "11"))
        self.assertNotEqual(drift.normalise("java8_command", "8"), drift.normalise("java17_command", "11"))
        self.tree.same_everywhere("")
        for line, opcode in (("8", "V1_8"), ("11", "V11"), ("17", "V17")):
            self.tree.write(line, "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java",
                            hooks(line, f"  int v = Opcodes.{opcode};\n"))
        self.assertEqual(0, self.tree.run("--update")[0])
        self.assertNotIn("Opcodes", (self.tree.root / "scripts/backport-drift.java11.diff").read_text())
        self.tree.write("11", "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java",
                        hooks("11", "  int v = Opcodes.V17;\n"))
        code, err = self.tree.run()
        self.assertEqual(1, code)
        self.assertIn("Opcodes.V17", err)

    def test_two_files_with_the_same_normalised_name_are_refused(self):
        self.tree.same_everywhere("")
        self.tree.write("11", "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>Extra.java", "class A {}\n")
        (self.tree.root / "agent-java11/src/main/java/io/ohmyrasp/agent/java11/Java<N>Extra.java").write_text("class B {}\n")
        with self.assertRaises(SystemExit) as raised:
            self.tree.run("--update")
        self.assertIn("same name", str(raised.exception))

    def test_recorded_syntax_difference_passes(self):
        self.tree.same_everywhere("  String a = f();\n")
        self.tree.write("11", "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java", hooks("11", "  var a = f();\n"))
        self.assertEqual(0, self.tree.run("--update")[0])
        recorded = (self.tree.root / "scripts/backport-drift.java11.diff").read_text()
        self.assertIn("-  String a = f();\n+  var a = f();", recorded)
        self.assertIn("== src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java", recorded)
        # The release number in the build file is a real per-line difference and is recorded too.
        self.assertIn("-options.release.set(8)\n+options.release.set(11)", recorded)
        self.assertEqual(0, self.tree.run()[0])

    def test_change_in_one_line_only_fails(self):
        self.tree.same_everywhere("  String a = f();\n")
        self.tree.run("--update")
        self.tree.write("8", "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java",
                        hooks("8", "  String a = f();\n  if (a == null) return;\n"))
        code, err = self.tree.run()
        self.assertEqual(1, code)
        self.assertIn("backport-drift.java11.diff does not record", err)
        self.assertIn("backport-drift.java17.diff does not record", err)
        self.assertIn("+-  if (a == null) return;", err)
        self.assertIn("make the same change in each", err)

    def test_same_change_in_every_line_passes_without_update(self):
        self.tree.same_everywhere("  String a = f();\n")
        self.tree.run("--update")
        self.tree.same_everywhere("  String a = f();\n  if (a == null) return;\n")
        self.assertEqual(0, self.tree.run()[0])

    def test_edit_inside_a_recorded_difference_fails(self):
        self.tree.same_everywhere("  String a = f();\n")
        self.tree.write("17", "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java", hooks("17", "  var a = f();\n"))
        self.tree.run("--update")
        self.tree.write("8", "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>RaspHooks.java", hooks("8", "  String a = g();\n"))
        code, err = self.tree.run()
        self.assertEqual(1, code)
        self.assertIn("String a = g();", err)

    def test_file_in_one_line_only_is_reported(self):
        self.tree.same_everywhere("")
        self.tree.run("--update")
        self.tree.write("8", "src/main/java/io/ohmyrasp/agent/java<N>/Java<N>Extra.java", "class Java8Extra {}\n")
        code, err = self.tree.run()
        self.assertEqual(1, code)
        self.assertIn("only in agent-java8", err)

    def test_line_tests_are_not_compared(self):
        self.tree.same_everywhere("")
        self.tree.run("--update")
        self.tree.write("11", "src/test/java/io/ohmyrasp/agent/java<N>/OnlyHereTest.java", "class OnlyHereTest {}\n")
        self.assertEqual(0, self.tree.run()[0])

    def test_missing_record_fails(self):
        self.tree.same_everywhere("")
        self.assertEqual(1, self.tree.run()[0])


if __name__ == "__main__":
    unittest.main()
