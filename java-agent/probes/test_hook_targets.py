"""Guards for the hook-targets probe: its library list, its recorded maps and the two coverage rules on them.

Run: python3 -m unittest discover -s java-agent/probes -p 'test_*.py'

The recorded maps are what the probe compares the packaged agents with; these tests read the committed
files only, so they run without Docker. check.py runs the same two rules after every comparison.
"""
import hashlib
import importlib.util
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
JAVA_AGENT = HERE.parent
PROBE = HERE / "hook-targets"

spec = importlib.util.spec_from_file_location("hookmap", PROBE / "hookmap.py")
hookmap = importlib.util.module_from_spec(spec)
sys.modules["hookmap"] = hookmap
spec.loader.exec_module(hookmap)
spec = importlib.util.spec_from_file_location("hook_targets_check", PROBE / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def gradle_modules(text: str) -> list[tuple[str, str, str]]:
    """What the stageHookTargets task in java-agent/build.gradle.kts reads from libraries.toml, line by line."""
    modules, group, artifact = [], "", ""
    for line in text.splitlines():
        if line.startswith("[[library]]"):
            group = artifact = ""
        elif line.startswith("group = "):
            group = line.split('"')[1]
        elif line.startswith("artifact = "):
            artifact = line.split('"')[1]
        elif line.startswith("versions = "):
            modules += [(group, artifact, v) for v in re.findall(r'"([^"]+)"', line.split("=", 1)[1])]
    return modules


def hook_map(units, rows):
    return hookmap.HookMap(tuple(units), "", tuple(hookmap.Row(lib, ver, "C", "m", "()V", "io/ohmyrasp/agent/H.x", tuple(by.split(",")))
                                                   for lib, ver, by in rows))


class LibraryListTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = hookmap.LIBRARIES.read_text()
        cls.libraries = hookmap.load_libraries()

    def test_gradle_reads_what_tomllib_reads(self):
        # The Gradle task has a line parser, not a TOML one: a field on two lines would stage the wrong versions.
        expected = [(lib.group, lib.artifact, v) for lib in self.libraries for v in lib.versions]
        self.assertEqual(gradle_modules(self.text), expected)

    def test_every_library_says_why_these_versions(self):
        self.assertGreater(len(self.libraries), 40)
        for lib in self.libraries:
            self.assertTrue(lib.why.strip(), f"{lib.id} needs a `why`")
            self.assertTrue(lib.versions, f"{lib.id} lists no version")
            self.assertEqual(len(set(lib.versions)), len(lib.versions), f"{lib.id} repeats a version")

    def test_a_coordinate_is_listed_once(self):
        ids = [lib.id for lib in self.libraries]
        self.assertEqual(sorted(ids), sorted(set(ids)))

    def test_none_names_listed_versions_and_gives_a_reason(self):
        for lib in self.libraries:
            for version, reason in lib.none.items():
                self.assertIn(version, lib.versions, f"{lib.id}: `none` names {version}, which is not in `versions`")
                self.assertTrue(str(reason).strip(), f"{lib.id} {version}: `none` needs a reason")


class RecordedMapsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.libraries = hookmap.load_libraries()
        cls.maps = hookmap.load_recorded()
        cls.allowlist = hookmap.load_allowlist()

    def test_maps_are_not_empty(self):
        # A scan that silently found nothing would make the guards below pass.
        for family, recorded in self.maps.items():
            self.assertGreater(len(hookmap.named_rows(recorded)), 500, family)
            self.assertGreater(len(recorded.units), 20, family)

    def test_rows_are_sorted_and_unique(self):
        for family in hookmap.FAMILIES:
            rows = [line for line in (hookmap.RECORDED / f"{family}.txt").read_text().splitlines() if line and not line.startswith("#")]
            self.assertEqual(rows, sorted(set(rows)), f"{family}.txt is not the sorted output of the checker")

    def test_no_backport_transformer_depends_on_the_ones_before_it(self):
        # A "# chain:" line is a transformer that adds something else after its predecessors than on the original
        # class; production chains them, so the line is a finding to look at before it is recorded.
        self.assertEqual(self.maps["backport"].chain, ())

    def test_rows_only_name_listed_library_versions(self):
        listed = {(lib.id, v) for lib in self.libraries for v in lib.versions}
        for family, recorded in self.maps.items():
            self.assertLessEqual({(row.library, row.version) for row in recorded.rows}, listed, family)

    def test_backport_map_carries_no_version_token(self):
        text = (hookmap.RECORDED / "backport.txt").read_text()
        self.assertNotRegex(text, r"Java(8|11|17)[A-Z]|agent/java(8|11|17)/")
        self.assertIn(hookmap.TOKEN, text)

    def test_every_library_version_is_hooked_or_says_why_not(self):
        self.assertEqual(hookmap.check_library_versions(self.libraries, self.maps), [])

    def test_every_hook_family_hooks_a_library_or_is_allowlisted(self):
        self.assertEqual(hookmap.check_units(self.maps, self.allowlist), [])

    def test_generated_summary_is_current(self):
        run = subprocess.run([sys.executable, str(JAVA_AGENT / "scripts" / "gen-hook-targets.py"), "--check"],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)


class GuardTest(unittest.TestCase):
    """The guards on small maps, so that a failure message and the floor on the allowlist are pinned."""

    def libraries(self, versions=("1", "2"), none=None):
        return [hookmap.Library("g", "a", tuple(versions), "why", none or {})]

    def test_version_without_a_hook_fails(self):
        maps = {"primary": hook_map(["U"], [("g:a", "1", "U")]), "backport": hook_map(["T"], [])}
        problems = hookmap.check_library_versions(self.libraries(), maps)
        self.assertEqual(len(problems), 1)
        self.assertIn("g:a 2 has no hooked method", problems[0])

    def test_version_without_a_hook_passes_when_none_says_why(self):
        maps = {"primary": hook_map(["U"], [("g:a", "1", "U")]), "backport": hook_map(["T"], [])}
        self.assertEqual(hookmap.check_library_versions(self.libraries(none={"2": "removed"}), maps), [])

    def test_hook_on_either_family_counts(self):
        maps = {"primary": hook_map(["U"], [("g:a", "1", "U")]), "backport": hook_map(["T"], [("g:a", "2", "T")])}
        self.assertEqual(hookmap.check_library_versions(self.libraries(), maps), [])

    def test_shared_call_site_rows_do_not_count_as_a_hook(self):
        maps = {"primary": hook_map(["U"], [("g:a", "1", "U"), ("g:a", "2", hookmap.COMMON)]), "backport": hook_map(["T"], [])}
        self.assertEqual(len(hookmap.check_library_versions(self.libraries(), maps)), 1)

    def test_none_for_a_hooked_version_fails(self):
        maps = {"primary": hook_map(["U"], [("g:a", "1", "U"), ("g:a", "2", "U")]), "backport": hook_map([], [])}
        self.assertIn("is hooked, but", hookmap.check_library_versions(self.libraries(none={"2": "gone"}), maps)[0])

    def test_unit_that_hooks_nothing_fails_unless_allowlisted(self):
        maps = {"primary": hook_map(["U", "Idle"], [("g:a", "1", "U")]), "backport": hook_map(["T"], [("g:a", "1", "T")])}
        problems = hookmap.check_units(maps, {"primary": {}, "backport": {}})
        self.assertEqual(len(problems), 1)
        self.assertIn("primary: Idle hooks no method", problems[0])
        self.assertEqual(hookmap.check_units(maps, {"primary": {"Idle": "JDK-only"}, "backport": {}}), [])

    def test_allowlist_is_a_floor(self):
        maps = {"primary": hook_map(["U"], [("g:a", "1", "U")]), "backport": hook_map(["T"], [("g:a", "1", "T")])}
        problems = hookmap.check_units(maps, {"primary": {"U": "JDK-only", "Gone": "x"}, "backport": {"T": " "}})
        self.assertEqual(len(problems), 4)
        self.assertTrue(any("U is no longer needed" in p for p in problems))
        self.assertTrue(any("Gone names no unit" in p for p in problems))
        self.assertTrue(any("T has no reason" in p for p in problems))
        self.assertTrue(any("T is no longer needed" in p for p in problems))

    def test_shared_call_site_rows_do_not_save_a_unit(self):
        maps = {"primary": hook_map(["U"], [("g:a", "1", hookmap.COMMON)]), "backport": hook_map([], [])}
        self.assertEqual(len(hookmap.check_units(maps, {"primary": {}, "backport": {}})), 1)


class ParsingTest(unittest.TestCase):
    ROW = ("g:a 1 pkg/C m (I)V -> io/ohmyrasp/agent/java8/Java8RaspHooks.before (reflective) @ Java8XTransformer,Java8YTransformer")

    def test_normalise_replaces_the_version_token_of_a_backport(self):
        for track in ("8", "11", "17"):
            text = self.ROW.replace("java8", f"java{track}").replace("Java8", f"Java{track}")
            self.assertEqual(hookmap.normalise(text, track), self.ROW.replace("java8", "java{N}").replace("Java8", "Java{N}"))

    def test_normalise_keeps_the_primary_as_it_is(self):
        self.assertEqual(hookmap.normalise(self.ROW, "main"), self.ROW)

    def test_parse_reads_units_rows_and_callee_with_spaces(self):
        parsed = hookmap.parse("# units (2): A B\n# libraries: 1, classes: 2, unreadable by the agent's ASM: 0\n" + self.ROW + "\n")
        self.assertEqual(parsed.units, ("A", "B"))
        row, = parsed.rows
        self.assertEqual((row.library, row.version, row.cls, row.method, row.descriptor), ("g:a", "1", "pkg/C", "m", "(I)V"))
        self.assertTrue(row.callee.endswith("before (reflective)"))
        self.assertEqual(row.units, ("Java8XTransformer", "Java8YTransformer"))

    def test_parse_reads_the_call_count_and_chain_findings(self):
        text = ("# units (1): A\n# chain: lib 1 pkg/C A adds 1 methods and 1 calls after its predecessors, 0 methods and 0 calls on the original class\n"
                "g:a 1 META-INF/versions/9/pkg/C m ()V -> io/Hooks.before x3 @ A\n"
                "g:a 1 pkg/C m ()V -> io/Hooks.before (reflective) @ A\n")
        parsed = hookmap.parse(text)
        self.assertEqual([(r.cls, r.callee, r.calls) for r in parsed.rows],
                         [("META-INF/versions/9/pkg/C", "io/Hooks.before", 3), ("pkg/C", "io/Hooks.before (reflective)", 1)])
        self.assertEqual(len(parsed.chain), 1)

    def test_parse_rejects_text_that_is_not_a_map(self):
        with self.assertRaises(ValueError):
            hookmap.parse("hello\n")


class ExpectationTableTest(unittest.TestCase):
    """The run-time table (io.ohmyrasp.agent.hookmiss.HookExpectations reads it): its format, callees and integrity trailer."""

    MAP = ("# units (1): ExpressionHookModule\n"
           "g:a 1 pkg/C m (I)V -> io/ohmyrasp/agent/hook/OhMyRaspHooks.beforeA x2 @ ExpressionHookModule\n"
           "g:a 1 pkg/C m (I)V -> io/ohmyrasp/agent/hook/OhMyRaspHooks.beforeB @ ExpressionHookModule\n"
           "g:a 2 pkg/C n ()V -> io/ohmyrasp/agent/hook/OhMyRaspHooks.evaluate (reflective) @ ExpressionHookModule\n"
           "g:a 1 pkg/E m ()V -> io/ohmyrasp/agent/hook/OhMyRaspHooks.beforeD @ ExpressionHookModule\n")

    def table(self, family="primary", hook_miss=None):
        return hookmap.expectation_table(family, hookmap.parse(self.MAP), hook_miss or {})

    def test_callee_name_drops_the_owner_and_the_reflective_mark(self):
        self.assertEqual(hookmap.callee_name("io/ohmyrasp/agent/hook/OhMyRaspHooks.beforeX"), "beforeX")
        self.assertEqual(hookmap.callee_name("io/ohmyrasp/agent/hook/OhMyRaspHooks.evaluate (reflective)"), "evaluate")

    def test_each_method_lists_the_callees_the_map_shows_from_it(self):
        rows = [line for line in self.table().splitlines() if not line.startswith("#")]
        self.assertEqual(rows, ["ExpressionHookModule pkg/C report m(I)V=beforeA,beforeB n()V=evaluate",
                                "ExpressionHookModule pkg/E report m()V=beforeD"])

    def test_the_table_names_its_family_and_ends_with_its_row_count_and_digest(self):
        text = self.table()
        lines = text.splitlines()
        self.assertIn("#! family primary", lines)
        self.assertLess(lines.index("#! family primary"), next(i for i, l in enumerate(lines) if not l.startswith("#")))
        body, trailer = text[:text.rindex("#! end ")], text[text.rindex("#! end "):]
        self.assertEqual(trailer.strip(), f"#! end rows=2 sha256={hashlib.sha256(body.encode()).hexdigest()}")

    def test_a_pair_the_exemptions_leave_out_is_not_a_row_or_counted(self):
        never = {("ExpressionHookModule", "pkg/E"): hookmap.MissPair("ExpressionHookModule", "pkg/E", "never", "because")}
        text = self.table(hook_miss=never)
        self.assertNotIn("pkg/E", text)
        self.assertIn("#! end rows=1 ", text)

    def test_the_committed_tables_end_with_a_digest_of_what_precedes_them(self):
        for family in hookmap.FAMILIES:
            text = (hookmap.EXPECTATIONS / f"{family}.txt").read_text()
            body, trailer = text[:text.rindex("#! end ")], text[text.rindex("#! end "):]
            rows = [line for line in body.splitlines() if line and not line.startswith("#")]
            self.assertIn(f"#! family {family}", body.splitlines())
            self.assertEqual(trailer.strip(), f"#! end rows={len(rows)} sha256={hashlib.sha256(body.encode()).hexdigest()}")
            for row in rows:
                self.assertTrue(all("=" in token for token in row.split(" ")[3:]), row)


class StagedTreeTest(unittest.TestCase):
    def test_staged_tree_must_match_the_list(self):
        libraries = [hookmap.Library("g", "a", ("1", "2"), "why", {})]
        with tempfile.TemporaryDirectory() as tmp:
            for rel in ("g/a/1/a-1.jar", "g/a/3/a-3.jar"):
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True)
                path.write_bytes(b"")
            problems = check.staged_problems(Path(tmp), libraries)
        self.assertEqual(problems, ["not staged: g/a/2", "staged but not in libraries.toml: g/a/3"])


class VerifyDependencyTest(unittest.TestCase):
    def test_probe_toml_stages_each_pinned_dependency_once(self):
        # check.py pins the digest, probe.toml says where run.py stages the JAR: the two lists must be the same.
        fixtures = [f for f in tomllib.loads((PROBE / "probe.toml").read_text())["fixture"] if f["flag"] == "--verify-dependency"]
        staged = [f["stage"][1] for f in fixtures]
        self.assertEqual(sorted(staged), sorted(check.VERIFY_DEPENDENCIES))
        for fixture in fixtures:
            _, artifact, version = fixture["stage"][1].split(":")
            self.assertEqual(fixture["stage"], ["--download-dependency", fixture["stage"][1], "{path}"])
            # build/runtime-probes/*.jar is what agent.yml carries to the runtime matrix.
            self.assertEqual(fixture["path"], f"build/runtime-probes/hook-verify-{artifact}-{version}.jar")

    def test_a_coordinate_that_is_not_pinned_is_refused(self):
        with self.assertRaises(SystemExit):
            check.download_dependency("org.example:unpinned:1.0", Path(tempfile.gettempdir()) / "never-written.jar")


if __name__ == "__main__":
    unittest.main()
