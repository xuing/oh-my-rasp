"""Unit tests for scripts/check-docs.py pattern boundaries.

Run: python3 -m unittest discover -s scripts -p 'test_check_docs.py'
"""
from __future__ import annotations

import importlib.util
import subprocess
import tempfile
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
            '<a id="custom-anchor"></a>',
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

    def test_emphasis_and_code_markers_are_stripped(self) -> None:
        # Item 5, review counterexample: "### Process _launches_" keeps GitHub's anchor process-launches.
        self.assertEqual(check_docs.heading_anchors("### Process _launches_"), {"process-launches"})
        self.assertEqual(check_docs.heading_anchors("## **Bold** and __strong__ `_raw_`"), {"bold-and-strong-_raw_"})
        self.assertEqual(check_docs.heading_anchors("## request_scanner"), {"request_scanner"})

    def test_html_anchors_keep_their_case(self) -> None:
        # Item 5, review counterexample: <a id="Case-Sensitive"> is not reached by #case-sensitive.
        self.assertEqual(check_docs.heading_anchors('<a id="Case-Sensitive"></a>'), {"Case-Sensitive"})

    def test_unmodelled_heading_shapes_fail(self) -> None:
        for text in ("Title\n=====", "Title\n---", "## ![logo](x.png) Intro"):
            with self.subTest(text=text), self.assertRaises(check_docs.UnsupportedHeading):
                check_docs.heading_anchors(text)
        self.assertEqual(check_docs.heading_anchors("- item\n---\n| a |\n|---|"), set())  # a rule, not a heading

    def test_real_anchor_targets(self) -> None:
        self.assertIn("process-launches", check_docs.anchors_of("docs/detection.md"))
        self.assertIn("rules-the-jdk-25-runtime-suite-requires",
                      check_docs.anchors_of("java-agent/docs/DETECTION-COVERAGE.md"))


LEDGER = "docs/development/vulhub-coverage.md"


class LedgerTest(unittest.TestCase):
    SCRIPTS = {
        "acceptance/vulhub/x/a-java8.sh": 'check "java8_file_sensitive_read"\nshell_path=/tmp/x\nrun_case\n',
        "acceptance/vulhub/x/b-java8.sh": 'check "java8_file_script_write"\n',
    }

    def problems(self, row: str) -> list[str]:
        return check_docs.ledger_row_problems(LEDGER, 1, row, self.SCRIPTS.get)

    def test_true_claim_passes(self) -> None:
        self.assertEqual(self.problems(
            "- [x] X (`scenario`; real Java8 acceptance: `acceptance/vulhub/x/a-java8.sh` blocks"
            " `java8_file_sensitive_read`)"), [])
        self.assertEqual(self.problems(
            "`java-agent/acceptance/vulhub/x/a-java8.sh` blocks the read with `java8_file_sensitive_read`"), [])

    def test_every_catalogue_id_after_the_script_is_a_claim(self) -> None:
        for row in ("`acceptance/vulhub/x/a-java8.sh` blocks `java8_file_script_write`",
                    "`acceptance/vulhub/x/a-java8.sh` recorded `java8_file_script_write`",
                    "`acceptance/vulhub/x/a-java8.sh` blocks `Foo.bar` with `java8_file_script_write`"):
            with self.subTest(row=row):
                [problem] = self.problems(row)
                self.assertIn("`acceptance/vulhub/x/a-java8.sh` never names `java8_file_script_write`", problem)
        # A bare backport family is a catalogue id too.
        [problem] = self.problems("`acceptance/vulhub/x/a-java8.sh` blocks `file_sensitive_read`")
        self.assertIn("never names `file_sensitive_read`", problem)

    def test_ids_before_the_first_script_name_the_subject(self) -> None:
        # request_path_confusion and java8_file_script_write describe the row's scenario, not the script.
        self.assertEqual(self.problems(
            "- [x] F (`request_path_confusion`, `java8_file_script_write`; real Java8 acceptance:"
            " `acceptance/vulhub/x/a-java8.sh` blocks `java8_file_sensitive_read`)"), [])

    def test_only_catalogue_ids_are_claims(self) -> None:
        # Item 1, review counterexample: the shell function run_case is prose, not a rule id.
        for word in ("run_case", "shell_path", "missing_expected_rule", "Foo.bar", "/etc/passwd"):
            with self.subTest(word=word):
                self.assertEqual(self.problems(f"`acceptance/vulhub/x/a-java8.sh` calls `{word}` and blocks"
                                               " `java8_file_sensitive_read`"), [])

    def test_unknown_line_prefixed_ids_fail(self) -> None:
        # Item 1: java8_/java11_/java17_ is used for rule ids only, so an unknown one is a mistake, on any part of the row.
        for row in ("`acceptance/vulhub/x/a-java8.sh` blocks `java8_no_such_rule`",
                    "- [x] Z (`java17_no_such_rule`; real Java17 acceptance: `acceptance/vulhub/x/a-java8.sh`)"):
            with self.subTest(row=row):
                [problem] = self.problems(row)
                self.assertIn("unknown rule id `java", problem)
        self.assertEqual(self.problems("`acceptance/vulhub/x/a-java8.sh` greps `java8_*` and `java17_rc=0`"), [])

    def test_claims_are_collected_over_the_whole_row(self) -> None:
        # Item 2, review counterexample: the script is on the row's first line and the claim three lines down.
        rows = check_docs.ledger_rows("\n".join([
            "- `acceptance/vulhub/x/a-java8.sh` runs the",
            "  acceptance. Protected mode",
            "  blocks the write with",
            "  `java8_file_script_write`.",
            "- `acceptance/vulhub/x/b-java8.sh` blocks `java8_file_script_write`.",
            "",
            "Prose line one",
            "prose line two",
        ]))
        self.assertEqual([no for no, _ in rows], [1, 5, 7, 8])
        first, row = rows[0]
        self.assertEqual(check_docs.ledger_row_problems(LEDGER, first, row, self.SCRIPTS.get), [
            f"ledger: {LEDGER}:4: `acceptance/vulhub/x/a-java8.sh` never names `java8_file_script_write`;"
            " say what the script asserts"])

    def test_a_claim_needs_one_of_the_rows_scripts(self) -> None:
        # Item 3, review counterexample: two scripts, each with its own true claim.
        for row in ("`acceptance/vulhub/x/a-java8.sh` blocks `java8_file_sensitive_read` and"
                    " `acceptance/vulhub/x/b-java8.sh` blocks `java8_file_script_write`",
                    "`acceptance/vulhub/x/b-java8.sh` and `acceptance/vulhub/x/a-java8.sh` block"
                    " `java8_file_sensitive_read`"):
            with self.subTest(row=row):
                self.assertEqual(self.problems(row), [])
        [problem] = self.problems("`acceptance/vulhub/x/a-java8.sh` and `acceptance/vulhub/x/b-java8.sh` block"
                                  " `java8_command_execution_exploit_primitive`")
        self.assertIn("none of `acceptance/vulhub/x/a-java8.sh`, `acceptance/vulhub/x/b-java8.sh` names", problem)

    def test_missing_script(self) -> None:
        [problem] = self.problems("real acceptance: `acceptance/vulhub/x/renamed-java8.sh`")
        self.assertIn("`acceptance/vulhub/x/renamed-java8.sh` is not a tracked script", problem)

    def test_script_references(self) -> None:
        # Item 4: a code span or a link destination names a script; a path ends at ".sh" followed by
        # none of [\w./-], so the review's ".sh/typo" is a different, untracked path.
        mentions = lambda text: [p for _, p in check_docs.script_mentions(LEDGER, text)]  # noqa: E731
        self.assertEqual(mentions("`acceptance/vulhub/x/a-java8.sh`"), ["acceptance/vulhub/x/a-java8.sh"])
        self.assertEqual(mentions("[Tomcat](../../java-agent/acceptance/vulhub/x/a-java8.sh#L3)"),
                         ["acceptance/vulhub/x/a-java8.sh"])
        for tail in (".bak", "/typo", "-old", ".d"):
            with self.subTest(tail=tail):
                self.assertEqual(mentions(f"`acceptance/vulhub/x/a-java8.sh{tail}`"),
                                 [f"acceptance/vulhub/x/a-java8.sh{tail}"])
        self.assertEqual(mentions("`acceptance/vulhub/x/a-java8.sh:12`"), ["acceptance/vulhub/x/a-java8.sh"])
        for text in ("`acceptance/vulhub/<component>/<scenario>-<jdk>.sh`", "run acceptance/vulhub/x/a-java8.sh",
                     "[doc](../../java-agent/acceptance/README.md)", "[x](https://e.com/acceptance/vulhub/x/a.sh)"):
            with self.subTest(text=text):
                self.assertEqual(mentions(text), [])
        [problem] = self.problems("[Tomcat](../../java-agent/acceptance/vulhub/x/a-java8.sh/typo)")
        self.assertIn("`acceptance/vulhub/x/a-java8.sh/typo` is not a tracked script", problem)

    def test_unreferenced_scripts(self) -> None:
        ledger = "\n".join([
            "## Covered Targets",
            "- [x] A (`a`; `acceptance/vulhub/x/a-java8.sh`)",
            "- [x] B (`b`; <!-- `acceptance/vulhub/z/c-java17.sh` --> `java-agent/acceptance/vulhub/y/b-java11.sh`)",
            "- [x] F (`f`; real Java17 acceptance:",
            "  [script](../../java-agent/acceptance/vulhub/z/f-java17.sh))",
            "",
            "`acceptance/vulhub/z/d-java17.sh` is named in prose, not on a row",
            "## Candidates",
            "- [x] `acceptance/vulhub/z/e-java17.sh`",
        ])
        scripts = ["acceptance/vulhub/x/a-java8.sh", "acceptance/vulhub/y/b-java11.sh", "acceptance/vulhub/z/c-java17.sh",
                   "acceptance/vulhub/z/d-java17.sh", "acceptance/vulhub/z/e-java17.sh", "acceptance/vulhub/z/f-java17.sh"]
        self.assertEqual(check_docs.unreferenced_scripts(ledger, scripts),
                         ["acceptance/vulhub/z/c-java17.sh", "acceptance/vulhub/z/d-java17.sh",
                          "acceptance/vulhub/z/e-java17.sh"])


class RealLedgerTest(unittest.TestCase):
    """The review's counterexamples, run against the real ledger rows and scripts."""

    @staticmethod
    def row(*needles: str) -> str:
        [found] = [row for row in check_docs.covered_rows(check_docs.read(LEDGER)) if all(n in row for n in needles)]
        return found

    def problems(self, row: str) -> list[str]:
        return check_docs.ledger_row_problems(LEDGER, 1, row, check_docs.script_text)

    def test_weblogic_upload_row(self) -> None:
        row = self.row("weblogic/2894-java8.sh")
        self.assertEqual(self.problems(row), [])
        [problem] = self.problems(row.replace("fileUpload_multipart_script", "java8_missing_expected_rule"))
        self.assertIn("unknown rule id `java8_missing_expected_rule`", problem)
        [problem] = self.problems(row.replace("fileUpload_multipart_script", "java8_file_script_write"))
        self.assertIn("never names `java8_file_script_write`", problem)

    def test_struts2_upload_row(self) -> None:
        row = self.row("struts2/upload-java17.sh", "S2-066")
        self.assertEqual(self.problems(row), [])
        self.assertEqual(self.problems(row.replace(" blocks", " calls `run_case` and blocks")), [])
        [problem] = self.problems(row.replace("upload-java17.sh", "upload-java17.sh.bak"))
        self.assertIn("`acceptance/vulhub/struts2/upload-java17.sh.bak` is not a tracked script", problem)


class FixtureRepo:
    """A throwaway git repository that check_docs reads as its ROOT, for running a whole check."""

    def __init__(self, files: dict[str, str]) -> None:
        self.files = files

    @staticmethod
    def clear_caches() -> None:
        for cached in (check_docs.anchors_of, check_docs.acceptance_scripts, check_docs.script_text):
            cached.cache_clear()

    def __enter__(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        for rel, text in self.files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"]):
            subprocess.run(cmd, cwd=root, check=True, capture_output=True)
        self.saved = check_docs.ROOT
        check_docs.ROOT = root
        self.clear_caches()
        return root

    def __exit__(self, *exc: object) -> None:
        check_docs.ROOT = self.saved
        self.clear_caches()
        self.tmp.cleanup()


class CheckLinksEndToEndTest(unittest.TestCase):
    def test_check_links_over_a_fixture_tree(self) -> None:
        files = {
            "docs/a.md": "\n".join([
                "[ok](b.md#usage-1) [emphasis](b.md#process-launches) [html](b.md#Custom)",
                "[case](b.md#Usage)",
                "[query](b.md#usage?typo)",
                "[gone](missing.md)",
                "[img](c.md#intro) [img again](c.md#other)",
            ]),
            "docs/b.md": '## Usage\n## Usage\n### Process _launches_\n<a id="Custom"></a>\n',
            "docs/c.md": "## ![logo](logo.png) Intro\n",
        }
        problems: list[str] = []
        with FixtureRepo(files):
            check_docs.check_links(["docs/a.md"], problems)
        self.assertEqual(problems, [
            "links: docs/a.md:2: `b.md#Usage`: docs/b.md has no heading with anchor `#Usage`",
            "links: docs/a.md:3: `b.md#usage?typo`: docs/b.md has no heading with anchor `#usage?typo`",
            "links: docs/a.md:4: `missing.md` does not resolve to a tracked file",
            "links: docs/c.md:1: cannot compute GitHub's anchor for an image in the heading"
            " `## ![logo](logo.png) Intro`, so no link into docs/c.md (first: docs/a.md:5) has its anchor checked;"
            " write it as `## Title` or teach heading_anchors in scripts/check-docs.py the GitHub rule",
        ])


class CheckLedgersEndToEndTest(unittest.TestCase):
    def test_check_ledgers_over_a_fixture_tree(self) -> None:
        files = {
            "java-agent/acceptance/vulhub/x/a-java8.sh": 'check "java8_file_sensitive_read"\nrun_case\n',
            "java-agent/acceptance/vulhub/x/b-java8.sh": 'check "java8_file_script_write"\n',
            "java-agent/acceptance/vulhub/x/c-java8.sh": 'check "java8_file_script_write"\n',
            "docs/development/vulhub-coverage.md": "\n".join([
                "## Covered Targets",
                "",
                "- [x] A (`request_path_confusion`; real Java8 acceptance: `acceptance/vulhub/x/a-java8.sh`",
                "  calls `run_case` and blocks `java8_file_sensitive_read`)",
                "- [x] B (`b`; real Java8 acceptance: [script](../../java-agent/acceptance/vulhub/x/b-java8.sh)"
                " blocks `java8_file_script_write`)",
                "",
            ]),
            "docs/development/algorithm-coverage.md": "\n".join([
                "- `acceptance/vulhub/x/a-java8.sh` runs the",
                "  check and blocks `java8_file_script_write`.",
                "- `acceptance/vulhub/x/a-java8.sh/typo` and `java8_no_such_rule`.",
                "",
            ]),
        }
        problems: list[str] = []
        with FixtureRepo(files):
            check_docs.check_ledgers(problems)
        A = "docs/development/algorithm-coverage.md"
        self.assertEqual(problems, [
            f"ledger: {A}:2: `acceptance/vulhub/x/a-java8.sh` never names `java8_file_script_write`;"
            " say what the script asserts",
            f"ledger: {A}:3: `acceptance/vulhub/x/a-java8.sh/typo` is not a tracked script under java-agent/",
            f"ledger: {A}:3: unknown rule id `java8_no_such_rule`: java-agent/rules/*.json has no such backport"
            " family; correct it or describe the family there",
            "ledger: java-agent/acceptance/vulhub/x/c-java8.sh is not named on a Covered Targets row of"
            " docs/development/vulhub-coverage.md",
        ])


class RuntimeSuiteListTest(unittest.TestCase):
    def parse(self, body: str) -> list[str]:
        return gen_coverage.parse_required_algorithms(body, "jdk25.sh")

    def test_required_array_is_read_in_script_order(self) -> None:
        self.assertEqual(self.parse("required_algorithms=(\n  zeta_rule\n  alpha_rule\n  mid_rule\n)\n"),
                         ["zeta_rule", "alpha_rule", "mid_rule"])

    def test_reader_returns_the_array_bash_builds(self) -> None:
        # Bash evaluates the script's own array lines, so a reader that drops or truncates entries fails here.
        lines = (gen_coverage.ACCEPTANCE / "runtime" / "jdk25.sh").read_text(encoding="utf-8").split("\n")
        self.assertFalse([l for l in lines if "required_algorithms+=" in l], "extend this test to the appends")
        start = next(i for i, l in enumerate(lines) if l.startswith("required_algorithms=("))
        end = next(i for i in range(start, len(lines)) if lines[i].strip() == ")")
        bash = subprocess.run(["bash", "-c", "\n".join(lines[start:end + 1]) + '\nprintf "%s\\n" "${required_algorithms[@]}"'],
                              check=True, capture_output=True, text=True).stdout.split()
        self.assertGreater(len(bash), 2)
        self.assertEqual(gen_coverage.jdk25_required_algorithms(), list(dict.fromkeys(bash)))

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
