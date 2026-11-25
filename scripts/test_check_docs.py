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
            "## Usage",
            "## Usage",
            "```",
            "# not a heading",
            "```",
            '<a id="Custom-Anchor"></a>',
        ])
        self.assertEqual(check_docs.heading_anchors(text), {
            "java-agent", "process-launches", "request_scanner-and-jndi-lookups", "usage", "usage-1",
            "custom-anchor"})

    def test_real_anchor_targets(self) -> None:
        self.assertIn("process-launches", check_docs.anchors_of("docs/detection.md"))
        self.assertIn("rules-the-jdk-25-runtime-suite-requires",
                      check_docs.anchors_of("java-agent/docs/DETECTION-COVERAGE.md"))


class LedgerTest(unittest.TestCase):
    SCRIPTS = {"acceptance/vulhub/x/a-java8.sh": 'check "java8_file_sensitive_read"\n'}

    def problems(self, line: str) -> list[str]:
        return check_docs.ledger_line_problems("ledger.md:1", line, self.SCRIPTS.get)

    def test_true_claim_passes(self) -> None:
        self.assertEqual(self.problems(
            "- [x] X (`scenario`; real Java8 acceptance: `acceptance/vulhub/x/a-java8.sh` blocks"
            " `java8_file_sensitive_read`)"), [])
        self.assertEqual(self.problems(
            "`java-agent/acceptance/vulhub/x/a-java8.sh` blocks the read with `java8_file_sensitive_read`"), [])

    def test_claim_the_script_never_names(self) -> None:
        [problem] = self.problems("`acceptance/vulhub/x/a-java8.sh` blocks `java8_file_script_write`")
        self.assertIn("never names `java8_file_script_write`", problem)

    def test_claim_belongs_to_the_nearest_script(self) -> None:
        line = "`acceptance/vulhub/x/a-java8.sh` passes; `acceptance/vulhub/x/a-java8.sh` blocks `other_rule`"
        self.assertEqual(len(self.problems(line)), 1)

    def test_historical_and_unattributed_claims_are_not_checked(self) -> None:
        self.assertEqual(self.problems("`acceptance/vulhub/x/a-java8.sh` recorded `java8_old_rule`"), [])
        self.assertEqual(self.problems("the agent blocks `java8_old_rule`"), [])

    def test_missing_script(self) -> None:
        [problem] = self.problems("real acceptance: `acceptance/vulhub/x/renamed-java8.sh`")
        self.assertIn("`acceptance/vulhub/x/renamed-java8.sh` is not a tracked script", problem)

    def test_patterns_and_links_are_not_script_mentions(self) -> None:
        line = "see `acceptance/vulhub/<component>/<scenario>-<jdk>.sh` and [a](../../java-agent/acceptance/x.sh)"
        self.assertEqual(check_docs.script_mentions(line), [])

    def test_unreferenced_scripts(self) -> None:
        ledger = "- `acceptance/vulhub/x/a-java8.sh` blocks `r`\n- `java-agent/acceptance/vulhub/y/b-java11.sh`\n"
        scripts = ["acceptance/vulhub/x/a-java8.sh", "acceptance/vulhub/y/b-java11.sh", "acceptance/vulhub/z/c-java17.sh"]
        self.assertEqual(check_docs.unreferenced_scripts(ledger, scripts), ["acceptance/vulhub/z/c-java17.sh"])


class RuntimeSuiteListTest(unittest.TestCase):
    def test_required_array_is_read_in_script_order(self) -> None:
        required = gen_coverage.jdk25_required_algorithms()
        self.assertEqual(required[0], "request_internal_identity")
        self.assertEqual(len(required), len(set(required)))

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
