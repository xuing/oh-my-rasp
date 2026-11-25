"""Unit tests for scripts/check-docs.py pattern boundaries.

Run: python3 -m unittest discover -s scripts -p 'test_check_docs.py'
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("check_docs", Path(__file__).with_name("check-docs.py"))
assert _spec is not None and _spec.loader is not None
check_docs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_docs)


_gen_spec = importlib.util.spec_from_file_location(
    "gen_coverage", Path(__file__).resolve().parent.parent / "java-agent" / "scripts" / "gen-detection-coverage.py")
assert _gen_spec is not None and _gen_spec.loader is not None
gen_coverage = importlib.util.module_from_spec(_gen_spec)
_gen_spec.loader.exec_module(gen_coverage)


def counts(line: str) -> bool:
    plain = line.replace("**", "")
    return bool(
        any(p.search(plain) for p in (check_docs.COUNT_EN, check_docs.COUNT_EN_COMPOUND, check_docs.COUNT_ZH))
        or check_docs.table_count(plain))


class TokenTest(unittest.TestCase):
    def test_matches_whole_version_only(self) -> None:
        pat = check_docs.token("0.2.0")
        self.assertTrue(pat.search("build-all.sh 0.2.0 --keys-dir"))
        self.assertIsNone(pat.search("`v0.2.0`."))  # the v-prefixed form is its own tag entry
        self.assertIsNone(pat.search("10.2.0"))
        self.assertIsNone(pat.search("0.2.0.1"))
        self.assertIsNone(pat.search("0.2.0-alpha.1"))

    def test_prerelease_tag(self) -> None:
        pat = check_docs.token("v0.2.0-alpha.1")
        self.assertTrue(pat.search("git tag v0.2.0-alpha.1"))
        self.assertIsNone(pat.search("v0.2.0-alpha.10"))

    def test_image_ref(self) -> None:
        pat = check_docs.token("gradle:9.9.2-jdk25")
        self.assertTrue(pat.search('docker run gradle:9.9.2-jdk25 gradle build'))
        self.assertIsNone(pat.search("gradle:9.9.2-jdk25x"))


class CountTest(unittest.TestCase):
    def test_flags_codebase_counts(self) -> None:
        for line in [
            "**28** ASM hook modules",
            "54 `DetectorEngine` capabilities",
            "83 hand-curated benign inputs",
            "the 136-scenario list",
            "publishes 12 release assets",
            "Build and sign all five `.bee` packages",
            "defines nine alerts",
            "28 个 ASM hook 模块",
            "136 个场景",
            "12 个 Release 资产",
            "The suite covers 28 hooks",
            "| Hook families | 28 |",
            "| Scenarios | **136** |",
            "回放覆盖136个场景",
        ]:
            with self.subTest(line=line):
                self.assertTrue(counts(line))

    def test_ignores_ordinary_numbers(self) -> None:
        for line in [
            "HTTP/1.1 302 redirecting to /rasp/blocked",
            "two modes: monitor and block",
            "JDK 8, 11, 17, 21 and 25",
            "Tomcat 9, 10 and 11",
            "CVE-2021-44228",
            "listens on port 7070",
            "takes 1–2 minutes",
            "| Valkey | `600` req/`1m` |",
            "| Port | 7070 |",
        ]:
            with self.subTest(line=line):
                self.assertFalse(counts(line))


class PinTest(unittest.TestCase):
    def test_collects_pins_from_every_source(self) -> None:
        images, values = check_docs.pins()
        for name in ("golang", "gradle", "postgres", "clickhouse/clickhouse-server", "ghcr.io/yannh/kubeconform"):
            self.assertIn(name, images)
        for value in ("19.0", "26.10.12.13", ">=26"):
            self.assertIn(value, values)

    def test_any_tag_of_a_pinned_image_is_flagged(self) -> None:
        images, _ = check_docs.pins()
        self.assertIn("golang", images)
        pat = check_docs.re.compile(r"(?<![\w./-])golang:[\w.${}-]+")
        self.assertTrue(pat.search("docker run golang:1.20 go test"))  # an old tag is still a copy


class ReleaseAssetsTest(unittest.TestCase):
    def test_published_set_matches_expected_assets(self) -> None:
        _, published, expected = check_docs.release_workflow()
        self.assertEqual(len(published), expected)
        self.assertIn("ohmyrasp-shirudo-upatches-<version>.tar.gz", published)
        self.assertNotIn("ohmyrasp-shirudo-upatches.tar.gz", published)  # staging name, renamed in dist/


class LinkTest(unittest.TestCase):
    def test_link_forms(self) -> None:
        line = "see [a](<../x y.md>) and `[b](missing.md)`"
        targets = [next(g for g in m.groups() if g)
                   for m in check_docs.INLINE_LINK.finditer(check_docs.INLINE_CODE.sub("", line))]
        self.assertEqual(targets, ["../x y.md"])  # angle brackets stripped; code span ignored
        self.assertEqual(check_docs.REF_LINK.match("[build]: missing.md").group(1), "missing.md")


class AnchorTest(unittest.TestCase):
    def test_github_heading_slugs(self) -> None:
        text = "\n".join([
            "# Java agent",
            "### Process launches",
            "## `request_scanner` and [JNDI](x.md) lookups",
            "```",
            "# not a heading",
            "```",
            '<a id="Custom-Anchor"></a>',
        ])
        self.assertEqual(check_docs.heading_anchors(text), {
            "java-agent", "process-launches", "request_scanner-and-jndi-lookups", "custom-anchor"})

    def test_entities_are_decoded_before_slugging(self) -> None:
        # Review counterexample: GitHub renders "A &amp; B" as "A & B", whose slug is a--b.
        self.assertEqual(check_docs.heading_anchors("## A &amp; B"), {"a--b"})

    def test_a_repeat_takes_the_first_free_suffix(self) -> None:
        # Review counterexample: the third heading's own slug usage-1 is taken by the second "Usage".
        self.assertEqual(check_docs.heading_anchors("## Usage\n## Usage\n## Usage-1"), {"usage", "usage-1", "usage-1-1"})
        self.assertEqual(check_docs.heading_anchors("## Usage\n## Usage\n## Usage"), {"usage", "usage-1", "usage-2"})

    def test_unmodelled_heading_shapes_fail(self) -> None:
        for text in ("Title\n=====", "Title\n---", "## _Draft_ notes", "## ![logo](x.png) Intro"):
            with self.subTest(text=text), self.assertRaises(check_docs.UnsupportedHeading):
                check_docs.heading_anchors(text)
        self.assertEqual(check_docs.heading_anchors("- item\n---\n| a |\n|---|"), set())  # a rule, not a heading

    def test_real_anchor_targets(self) -> None:
        self.assertIn("process-launches", check_docs.anchors_of("docs/detection.md"))
        self.assertIn("rules-the-jdk-25-runtime-suite-requires",
                      check_docs.anchors_of("java-agent/docs/DETECTION-COVERAGE.md"))


class LedgerTest(unittest.TestCase):
    SCRIPTS = {
        "acceptance/vulhub/x/a-java8.sh": 'check "java8_file_sensitive_read"\nshell_path=/tmp/x\n',
        "acceptance/vulhub/x/b-java8.sh": 'check "java8_file_script_write"\n',
    }

    def problems(self, line: str) -> list[str]:
        return check_docs.ledger_line_problems("ledger.md:1", line, self.SCRIPTS.get)

    def test_true_claim_passes(self) -> None:
        self.assertEqual(self.problems(
            "- [x] X (`scenario`; real Java8 acceptance: `acceptance/vulhub/x/a-java8.sh` blocks"
            " `java8_file_sensitive_read`)"), [])
        self.assertEqual(self.problems(
            "`java-agent/acceptance/vulhub/x/a-java8.sh` blocks the read with `java8_file_sensitive_read`"), [])

    def test_every_catalogue_id_on_the_row_is_a_claim(self) -> None:
        for line in ("`acceptance/vulhub/x/a-java8.sh` blocks `java8_file_script_write`",
                     "`acceptance/vulhub/x/a-java8.sh` recorded `java8_file_script_write`",
                     "`acceptance/vulhub/x/a-java8.sh` blocks `Foo.bar` with `java8_file_script_write`"):
            with self.subTest(line=line):
                [problem] = self.problems(line)
                self.assertIn("`acceptance/vulhub/x/a-java8.sh` never names `java8_file_script_write`", problem)

    def test_a_claim_holds_for_every_script_on_the_row(self) -> None:
        # a-java8.sh names the id, b-java8.sh does not: the problem names b, wherever it sits on the row.
        for line in ("`acceptance/vulhub/x/a-java8.sh` and `acceptance/vulhub/x/b-java8.sh` block `java8_file_sensitive_read`",
                     "`acceptance/vulhub/x/b-java8.sh` and `acceptance/vulhub/x/a-java8.sh` block `java8_file_sensitive_read`"):
            with self.subTest(line=line):
                [problem] = self.problems(line)
                self.assertIn("`acceptance/vulhub/x/b-java8.sh` never names", problem)

    def test_row_labels_are_not_claims(self) -> None:
        # request_path_confusion is a catalogue id, here the scenario's label, not what the script asserts.
        self.assertEqual(self.problems(
            "- [x] F (`request_path_confusion`, `request_scenario_label`; real Java8 acceptance:"
            " `acceptance/vulhub/x/a-java8.sh` blocks `java8_file_sensitive_read`)"), [])

    def test_rule_shaped_words_outside_the_catalogue_fail(self) -> None:
        # shell_path is a variable in the script: a non-catalogue word is not evidence.
        for word in ("shell_path", "missing_expected_rule", "file_sensitive_read"):
            with self.subTest(word=word):
                [problem] = self.problems(f"`acceptance/vulhub/x/a-java8.sh` blocks `{word}`")
                self.assertIn(f"`{word}` is shaped like a rule id but", problem)
        self.assertEqual(self.problems("`acceptance/vulhub/x/a-java8.sh` reads `/etc/passwd` via `Foo.bar`"), [])

    def test_unattributed_claims_are_not_checked(self) -> None:
        self.assertEqual(self.problems("the agent blocks `java8_old_rule_name`"), [])

    def test_missing_script(self) -> None:
        [problem] = self.problems("real acceptance: `acceptance/vulhub/x/renamed-java8.sh`")
        self.assertIn("`acceptance/vulhub/x/renamed-java8.sh` is not a tracked script", problem)

    def test_a_path_ends_at_sh(self) -> None:
        self.assertEqual(check_docs.script_mentions("`acceptance/vulhub/x/a-java8.sh.bak`"),
                         [(1, "acceptance/vulhub/x/a-java8.sh.bak")])
        self.assertEqual(check_docs.script_mentions("run acceptance/vulhub/x/a-java8.sh."),
                         [(4, "acceptance/vulhub/x/a-java8.sh")])

    def test_patterns_and_links_are_not_script_mentions(self) -> None:
        line = "see `acceptance/vulhub/<component>/<scenario>-<jdk>.sh` and [a](../../java-agent/acceptance/x.sh)"
        self.assertEqual(check_docs.script_mentions(line), [])

    def test_unreferenced_scripts(self) -> None:
        ledger = "\n".join([
            "## Covered Targets",
            "- [x] A (`a`; `acceptance/vulhub/x/a-java8.sh`)",
            "- [x] B (`b`; <!-- `acceptance/vulhub/z/c-java17.sh` --> `java-agent/acceptance/vulhub/y/b-java11.sh`)",
            "`acceptance/vulhub/z/d-java17.sh` is named in prose, not on a row",
            "## Candidates",
            "- [x] `acceptance/vulhub/z/e-java17.sh`",
        ])
        scripts = ["acceptance/vulhub/x/a-java8.sh", "acceptance/vulhub/y/b-java11.sh", "acceptance/vulhub/z/c-java17.sh",
                   "acceptance/vulhub/z/d-java17.sh", "acceptance/vulhub/z/e-java17.sh"]
        self.assertEqual(check_docs.unreferenced_scripts(ledger, scripts),
                         ["acceptance/vulhub/z/c-java17.sh", "acceptance/vulhub/z/d-java17.sh",
                          "acceptance/vulhub/z/e-java17.sh"])


class RealLedgerTest(unittest.TestCase):
    """The review's counterexamples, run against the real ledger rows and scripts."""

    @staticmethod
    def row(*needles: str) -> str:
        [line] = [l for l in check_docs.read(check_docs.VULHUB_LEDGER).split("\n")
                  if l.startswith("- [x]") and all(n in l for n in needles)]
        return line

    @staticmethod
    def script(path: str) -> str | None:
        file = check_docs.ROOT / "java-agent" / path
        return file.read_text(encoding="utf-8") if path.endswith(".sh") and file.is_file() else None

    def problems(self, line: str) -> list[str]:
        return check_docs.ledger_line_problems("vulhub-coverage.md", line, self.script)

    def test_weblogic_upload_row(self) -> None:
        line = self.row("weblogic/2894-java8.sh")
        self.assertEqual(self.problems(line), [])
        [problem] = self.problems(line.replace("fileUpload_multipart_script", "missing_expected_rule"))
        self.assertIn("`missing_expected_rule` is shaped like a rule id but", problem)
        [problem] = self.problems(line.replace("fileUpload_multipart_script", "java8_file_script_write"))
        self.assertIn("never names `java8_file_script_write`", problem)

    def test_struts2_upload_row(self) -> None:
        line = self.row("struts2/upload-java17.sh", "S2-066")
        self.assertEqual(self.problems(line), [])
        [problem] = self.problems(line.replace("`fileUpload_multipart_script`", "`shell_path`"))
        self.assertIn("`shell_path` is shaped like a rule id but", problem)
        [problem] = self.problems(line.replace("upload-java17.sh", "upload-java17.sh.bak"))
        self.assertIn("`acceptance/vulhub/struts2/upload-java17.sh.bak` is not a tracked script", problem)


class RuntimeSuiteListTest(unittest.TestCase):
    def parse(self, body: str) -> list[str]:
        return gen_coverage.parse_required_algorithms(body, "jdk25.sh")

    def test_required_array_is_read_in_script_order(self) -> None:
        self.assertEqual(self.parse("required_algorithms=(\n  zeta_rule\n  alpha_rule\n  mid_rule\n)\n"),
                         ["zeta_rule", "alpha_rule", "mid_rule"])
        required = gen_coverage.jdk25_required_algorithms()
        self.assertEqual(required[:2], ["request_internal_identity", "request_default_jwt_secret"])

    def test_entry_forms(self) -> None:
        # Review counterexamples: quoted entries, trailing comments, an indented ")" and a later "+=".
        text = "\n".join([
            "required_algorithms=(",
            '  "request_internal_identity"',
            "  'request_default_jwt_secret'  # required",
            "  # a comment line",
            "  request_scanner request_internal_identity",
            "  )",
            'for a in "${required_algorithms[@]}"; do :; done  # ${#required_algorithms[@]} entries',
            'if [[ "$extra" == 1 ]]; then',
            "  required_algorithms+=(xss_echo)",
            "fi",
            "required_algorithms+=(",
            "  sql_userinput)",
        ])
        self.assertEqual(self.parse(text), ["request_internal_identity", "request_default_jwt_secret",
                                            "request_scanner", "xss_echo", "sql_userinput"])
        self.assertEqual(self.parse("local -a required_algorithms=(a_rule b_rule)"), ["a_rule", "b_rule"])

    def test_unreadable_forms_fail_with_the_line(self) -> None:
        cases = {
            "required_algorithms=(\n  a_rule\n  $EXTRA\n)": "jdk25.sh:3:",
            'required_algorithms=(\n  "${extra[@]}"\n)': "jdk25.sh:2:",
            "required_algorithms=(\n  a_rule\n": "jdk25.sh:1:",
            "required_algorithms=(a_rule) && true": "jdk25.sh:1:",
            "required_algorithms=(a_rule)\nrequired_algorithms[3]=b_rule": "jdk25.sh:2:",
            "required_algorithms+=(a_rule)\nrequired_algorithms=(b_rule)": "jdk25.sh:2:",
            "mapfile -t required_algorithms < list.txt": "jdk25.sh:1:",
            "echo none": "jdk25.sh:",
        }
        for text, where in cases.items():
            with self.subTest(text=text), self.assertRaises(SystemExit) as raised:
                self.parse(text)
            self.assertIn(where, str(raised.exception))

    def test_acceptance_assertions_are_whole_catalogue_tokens(self) -> None:
        # Review counterexamples: a capitalised id (weblogic/2894-java8.sh) and an id passed to a helper (java17.sh).
        asserted = gen_coverage.asserted_algorithms()
        self.assertIn("fileUpload_multipart_script", asserted)
        self.assertIn("java17_request_typed_payload_deserialization", asserted)
        catalogue = gen_coverage.rule_catalogue
        self.assertEqual(catalogue.asserted('expect_block "$v" java17_request_typed_payload_deserialization /x'),
                         {"java17_request_typed_payload_deserialization"})
        self.assertEqual(catalogue.asserted(
            'curl x > "${dir}/jmx_file_write.response"\n    jmx_file_write:/rasp/java8/jmx-file-write \\\n'
            "java8_jmx_file_writes /rasp/jmx_file_write"), set())

    def test_probe_names_primary_rules_only(self) -> None:
        checked = gen_coverage.probe_checked_rules()
        self.assertIn("servlet-admission", checked["request_scanner"])
        self.assertTrue(all(not name.startswith("java8_") for name in checked))


class SpliceTest(unittest.TestCase):
    def test_reversed_markers_fail(self) -> None:
        text = f"{gen_coverage.REGION_END}\nhand\n{gen_coverage.REGION_BEGIN}\n"
        with self.assertRaises(SystemExit):
            gen_coverage.splice_region(text, "x", Path("README.md"))

    def test_region_is_replaced_once(self) -> None:
        text = f"a\n{gen_coverage.REGION_BEGIN}\nold\n{gen_coverage.REGION_END}\nb\n"
        self.assertEqual(gen_coverage.splice_region(text, "NEW", Path("README.md")), "a\nNEW\nb\n")


class RegionTest(unittest.TestCase):
    def test_generated_region_is_blanked_but_lines_kept(self) -> None:
        text = "a\n<!-- BEGIN GENERATED metrics (x) -->\n| 28 hook modules |\n<!-- END GENERATED metrics -->\nb\n"
        blanked = check_docs.REGION.sub(lambda m: "\n" * m.group(0).count("\n"), text)
        self.assertNotIn("28", blanked)
        self.assertEqual(blanked.count("\n"), text.count("\n"))


if __name__ == "__main__":
    unittest.main()
