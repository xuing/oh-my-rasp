"""Tests for check-detector-parity.sh's call-site filter.

Run: python3 -m unittest discover -s java-agent/scripts -p 'test_check_detector_parity.py'
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-detector-parity.sh"
SYMBOL = "isMavenRepositoryArtifactWrite"


def fails(*sources: str) -> bool:
    """Whether require_symbol reports no call of SYMBOL in a tree holding these Java sources."""
    with tempfile.TemporaryDirectory() as directory:
        for index, source in enumerate(sources):
            Path(directory, f"S{index}.java").write_text(source)
        function = subprocess.run(["sed", "-n", "/^require_symbol() {/,/^}/p", str(SCRIPT)],
                                  capture_output=True, text=True, check=True).stdout
        run = subprocess.run(["bash", "-c", f'fail=0\n{function}\nrequire_symbol "$1" "$2"\necho "fail=$fail"',
                              "check", directory, SYMBOL], capture_output=True, text=True, check=True)
        return run.stdout.strip().endswith("fail=1")


class CallSiteTest(unittest.TestCase):
    def test_the_declaration_alone_is_not_a_call(self):
        self.assertTrue(fails(f"  private static boolean {SYMBOL}(String path) {{\n    return false;\n  }}\n"))

    def test_a_comment_is_not_a_call(self):
        self.assertTrue(fails(f"  // {SYMBOL}(path) guards the write rule\n", f"   * {SYMBOL}(path)\n"))

    def test_a_call_is_a_call(self):
        self.assertFalse(fails(f"  private static boolean {SYMBOL}(String path) {{\n    return false;\n  }}\n",
                               f"    if ({SYMBOL}(normalized)) {{\n      return null;\n    }}\n"))

    def test_a_declaration_with_array_or_generic_types_is_not_a_call(self):
        self.assertTrue(fails(f"  static final java.util.List<String[]> {SYMBOL}(String[] parts) {{\n"))


if __name__ == "__main__":
    unittest.main()
