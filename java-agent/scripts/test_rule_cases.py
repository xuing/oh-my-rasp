"""Guards for java-agent/rules/cases: the schema, the rule ids it names, and the coverage ratchet; and for the
catalogue's not_wired marking, which the sources must agree with.

Run: python3 -m unittest discover -s java-agent/scripts -p 'test_rule_cases.py'

The rule-cases probe checks that the engines do what the files declare; these tests check the files
themselves and need no agent build.
"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "probes" / "common"))
import rule_cases  # noqa: E402
import rule_catalogue  # noqa: E402
import rule_wiring  # noqa: E402

CATALOGUE = {"primary": rule_catalogue.primary_ids(), "backport": rule_catalogue.backport_families()}


class SchemaTest(unittest.TestCase):
    def test_every_case_file_follows_the_schema(self):
        try:
            rule_cases.load()
        except rule_cases.SchemaError as error:
            self.fail(f"case files do not follow the schema in probes/common/rule_cases.py:\n{error}")

    def test_the_scan_found_the_cases(self):
        # A loader that silently finds nothing would make every other check here pass.
        cases = rule_cases.load()
        self.assertGreaterEqual(len(cases), 100)
        self.assertGreaterEqual(len({c.file for c in cases}), 40)

    def test_rejects_an_attack_that_is_let_through_without_a_reason(self):
        _, errors = rule_cases.parse("readFile_unwanted", '''
[[case]]
name = "passwd"
kind = "attack"
via = "sink"
op = "file.read"
args = { path = "/etc/passwd" }
primary = { effect = "log", rule = "readFile_unwanted" }
backport = { effect = "block", rule = "file_sensitive_read" }
''')
        self.assertEqual(errors, ["readFile_unwanted::passwd [primary]: an attack expected to log says why"])

    def test_rejects_a_benign_case_that_fires_and_a_request_case_without_a_request(self):
        _, errors = rule_cases.parse("request_path_confusion", '''
[[case]]
name = "benign-admin"
kind = "benign"
via = "request"
primary = { effect = "log", rule = "request_path_confusion" }
backport = { effect = "none" }
''')
        self.assertIn("request_path_confusion::benign-admin: via request needs [case.request]", errors)
        self.assertIn("request_path_confusion::benign-admin [primary]: a benign case expects none", errors)

    def test_rejects_unknown_ops_and_arguments(self):
        _, errors = rule_cases.parse("command_common", '''
[[case]]
name = "shell"
kind = "benign"
via = "sink"
op = "process.exec"
args = { command = "echo" }
primary = { effect = "none" }
backport = { effect = "none" }
''')
        self.assertEqual(errors, ["command_common::shell: process.exec needs args argv",
                                  "command_common::shell: process.exec takes no args command"])


class CatalogueTest(unittest.TestCase):
    def test_every_file_is_named_for_a_rule_id(self):
        for path in rule_cases.case_files():
            self.assertIn(path.stem, CATALOGUE["primary"] | CATALOGUE["backport"],
                          f"{path.name}: name a case file for the primary id, or the backport family when the "
                          "primary has no counterpart")

    def test_every_rule_an_expectation_names_exists_on_that_engine(self):
        for case in rule_cases.load():
            for engine, expect in case.expect.items():
                unknown = set(expect.ids()) - CATALOGUE[engine]
                self.assertFalse(unknown, f"{case.id}: no {engine} rule {', '.join(sorted(unknown))} in rules/*.json"
                                 + (" (backport rules are families, without the java8_ prefix)" if engine == "backport" else ""))


class CoverageTest(unittest.TestCase):
    """A rule id is covered, or listed in uncovered.toml with a reason; the list only shrinks."""

    def test_every_rule_is_covered_or_listed(self):
        covered = rule_cases.covered(rule_cases.load())
        listed = rule_catalogue.with_not_wired(rule_cases.load_uncovered())
        for engine in rule_cases.ENGINES:
            missing = CATALOGUE[engine] - covered[engine] - set(listed[engine])
            self.assertFalse(missing, f"{engine} rule ids with no attack case that blocks or logs them in a file that "
                             f"also has a benign case, and not listed in rules/cases/uncovered.toml: "
                             f"{', '.join(sorted(missing))}")

    def test_no_listed_rule_is_covered(self):
        covered = rule_cases.covered(rule_cases.load())
        for engine, listed in rule_catalogue.with_not_wired(rule_cases.load_uncovered()).items():
            stale = set(listed) & covered[engine]
            self.assertFalse(stale, f"{engine} rule ids now covered by cases; take them off rules/cases/uncovered.toml: "
                             f"{', '.join(sorted(stale))}")

    def test_every_listed_rule_exists_and_has_a_reason(self):
        for engine, listed in rule_catalogue.with_not_wired(rule_cases.load_uncovered()).items():
            unknown = set(listed) - CATALOGUE[engine]
            self.assertFalse(unknown, f"uncovered.toml lists {engine} ids not in rules/*.json: {', '.join(sorted(unknown))}")
            for rule, reason in listed.items():
                self.assertTrue(reason.strip(), f"uncovered.toml: {engine} {rule} needs a reason")

    def test_a_not_wired_id_is_not_also_listed_in_uncovered_toml(self):
        # Its reason lives in the catalogue; a second copy could disagree with it.
        listed = set(rule_cases.load_uncovered()["primary"]) & rule_catalogue.not_wired().keys()
        self.assertFalse(listed, f"take {', '.join(sorted(listed))} off rules/cases/uncovered.toml: the catalogue's "
                         "not_wired reason is the one that is shown")
        self.assertEqual(rule_catalogue.with_not_wired(rule_cases.load_uncovered())["primary"].keys()
                         & rule_catalogue.not_wired().keys(), rule_catalogue.not_wired().keys())


class WiringTest(unittest.TestCase):
    """The catalogue's not_wired marking agrees with the sources, in both directions.

    scripts/rule_wiring.py reads which OhMyRaspHooks entry methods the hook modules and shared visitors inject
    and which rule ids the code behind them can report (its docstring says what it cannot see). A rule marked
    not wired that a hook can now reach, and a rule no hook can reach that is not marked, both fail here.
    """

    def test_the_analysis_found_the_agent(self):
        # A scan that silently finds nothing would make both checks below pass.
        self.assertGreaterEqual(len(rule_wiring.entry_methods()), 150)
        self.assertGreaterEqual(len(rule_wiring.named_in_emitters()), 60)
        self.assertGreaterEqual(len(rule_wiring.emitters()), 130)
        self.assertGreaterEqual(len(rule_wiring.reachable_ids()), 100)
        self.assertTrue(rule_wiring.is_reachable("OhMyRaspHooks", "beforeSql"))
        self.assertTrue(rule_wiring.is_reachable("ProcessDetector", "detectCommand"))
        self.assertFalse(rule_wiring.is_reachable("OhMyRaspHooks", "beforeEval"))

    def test_the_receiver_type_keeps_a_call_on_an_unrelated_type_apart(self):
        # `List.of(` and a call on a String or a List must not reach the agent method of the same name, and two
        # overloads with different numbers of parameters are two methods.
        self.assertTrue(rule_wiring.is_reachable("OhMyRaspHooks", "beforeHessianAllocation"))
        self.assertFalse(rule_wiring.is_reachable("OhMyRaspHooks", "beforeHessianType"))
        arities = {key[2] for key in rule_wiring.reachable_methods() if key[:2] == ("OhMyRaspHooks", "beforeProcessBuilderStart")}
        self.assertEqual({1, 2}, arities)

    def test_the_request_body_hooks_give_the_detectors_a_body(self):
        # The body the application reads reaches a request context through the request-body hooks (the exitBody*
        # entries RequestBodyVisitor injects), so the body-only rules (rule_wiring.BODY_ONLY) are reachable and none
        # of them is marked not wired. If this fails, that path is gone: measure the body-only rules again with the
        # rule-cases probe and mark those that no longer fire.
        self.assertIn(("OhMyRaspHooks", "settleBody", 2), rule_wiring.request_body_sources())
        self.assertTrue(rule_wiring.is_reachable("OhMyRaspHooks", "exitBodyRead"))
        self.assertFalse(rule_wiring.BODY_ONLY.keys() & rule_catalogue.not_wired().keys())

    def test_a_compatibility_stub_is_not_a_capability(self):
        self.assertIn(("DeserializationDetector", "detectHessianType"), rule_wiring.empty_stubs())
        self.assertNotIn(("DeserializationDetector", "detectHessianAllocation"), rule_wiring.empty_stubs())

    def test_every_marked_id_is_a_primary_id_with_a_reason(self):
        marked = rule_catalogue.not_wired()  # raises for an id outside its file's primary ids, or a blank reason
        self.assertTrue(marked)
        self.assertLessEqual(marked.keys(), rule_catalogue.primary_ids())

    def test_no_marked_id_has_become_reachable(self):
        reachable = rule_wiring.reachable_ids() & rule_catalogue.not_wired().keys()
        self.assertFalse(reachable, f"{', '.join(sorted(reachable))}: a hook module can now reach "
                         "the code that reports it, so take it off the not_wired object in rules/general.json (and "
                         "give it a rule case, or an entry in rules/cases/uncovered.toml)")

    def test_every_id_no_hook_reaches_is_marked(self):
        unmarked = rule_wiring.unreachable_primary_ids() - rule_catalogue.not_wired().keys()
        self.assertFalse(unmarked, f"{', '.join(sorted(unmarked))}: no hook module injects a call that reaches "
                         "the code that reports it, so a count must not present it as a detection. Add it to the "
                         "not_wired object beside its description in rules/general.json or product.json, or wire it")


if __name__ == "__main__":
    unittest.main()
