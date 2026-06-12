#!/usr/bin/env python3
"""Check the Java Vulhub coverage ledger for untracked targets and weak rows.

This is a lightweight guard for the manual Vulhub walkthrough process. It does
not run containers; it verifies that every scoped Java/JVM README path in the
local Vulhub snapshot is mentioned by the durable coverage ledger, algorithm
docs, or acceptance scripts, and that every checked Covered Targets row carries
either real acceptance evidence or an explicit boundary reason. It also checks
that the Source Audit summary counts match the snapshot.

Usage:
  python3 java-agent/scripts/check-vulhub-java-coverage.py [--vulhub-root PATH]

The default Vulhub snapshot path is read from VULHUB_ROOT, falling back to
/tmp/vulhub-ohmyrasp-20260603.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

JAVA_ROOTS = {
    "activemq",
    "aj-report",
    "apache-cxf",
    "apache-druid",
    "apereo-cas",
    "coldfusion",
    "confluence",
    "dataease",
    "dubbo",
    "elasticsearch",
    "fastjson",
    "flink",
    "geoserver",
    "glassfish",
    "h2database",
    "hadoop",
    "hertzbeat",
    "hugegraph",
    "jackson",
    "java",
    "jboss",
    "jenkins",
    "jetty",
    "jimureport",
    "jira",
    "jmeter",
    "kafka",
    "kkfileview",
    "liferay-portal",
    "linkis",
    "log4j",
    "metabase",
    "metersphere",
    "mojarra",
    "nacos",
    "neo4j",
    "nexus",
    "ofbiz",
    "openfire",
    "opentsdb",
    "rocketmq",
    "shiro",
    "skywalking",
    "solr",
    "spark",
    "spring",
    "struts2",
    "teamcity",
    "tomcat",
    "unomi",
    "weblogic",
    "xstream",
    "xxl-job",
}

EVIDENCE_TERMS = (
    "real ",
    "acceptance",
    "covered by",
    "same real",
    "legacy boundary",
    "source-availability boundary",
    "setup/license",
    "dependency-version boundary",
)
PLACEHOLDER = "- [ ] _Add the next Java Vulhub candidate here before probing it._"

AGENT_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = AGENT_ROOT.parent
CHECKLIST = REPO_ROOT / "docs" / "development" / "vulhub-coverage.md"
ALGORITHM_DOC = REPO_ROOT / "docs" / "development" / "algorithm-coverage.md"
SCRIPTS = AGENT_ROOT / "scripts"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def java_readmes(vulhub_root: Path) -> list[str]:
    paths: list[str] = []
    for readme in vulhub_root.glob("*/*/README.md"):
        rel = readme.relative_to(vulhub_root).as_posix()
        if rel.split("/", 1)[0] in JAVA_ROOTS:
            paths.append(rel)
    return sorted(paths)


def java_roots(vulhub_root: Path) -> list[str]:
    return sorted({rel.split("/", 1)[0] for rel in java_readmes(vulhub_root)})


def java_cve_tokens(vulhub_root: Path) -> list[str]:
    tokens: set[str] = set()
    for rel in java_readmes(vulhub_root):
        readme = vulhub_root / rel
        tokens.update(token.upper() for token in re.findall(r"CVE-\d{4}-\d{4,}", read_text(readme), flags=re.I))
    return sorted(tokens)


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def search_corpus(checklist: Path, algorithm_doc: Path, scripts_dir: Path) -> str:
    parts = [
        read_text(checklist),
        read_text(algorithm_doc),
    ]
    for script in sorted(scripts_dir.glob("acceptance*.sh")):
        parts.append(read_text(script))
    return "\n".join(parts)


def missing_readme_mentions(vulhub_root: Path, corpus: str) -> list[str]:
    missing: list[str] = []
    for rel in java_readmes(vulhub_root):
        token = rel.removesuffix("/README.md")
        if token not in corpus:
            missing.append(rel)
    return missing


def missing_cve_mentions(vulhub_root: Path, corpus: str) -> list[str]:
    return [token for token in java_cve_tokens(vulhub_root) if token not in corpus]


def covered_target_rows(checklist: Path) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    in_covered = False
    for lineno, line in enumerate(read_text(checklist).splitlines(), start=1):
        if line == "## Covered Targets":
            in_covered = True
            continue
        if line == "## Candidates":
            in_covered = False
        if in_covered and line.startswith("- [x]"):
            rows.append((lineno, line))
    return rows


def rows_without_evidence(checklist: Path) -> list[tuple[int, str]]:
    weak: list[tuple[int, str]] = []
    for lineno, row in covered_target_rows(checklist):
        lower = row.lower()
        if not any(term in lower for term in EVIDENCE_TERMS):
            weak.append((lineno, row))
    return weak


def source_audit_mismatches(vulhub_root: Path, checklist: Path) -> list[str]:
    checklist_text = read_text(checklist)
    scope_match = re.search(
        r"currently covers\s+(\d+)\s+Vulhub roots and\s+(\d+)\s+README\s+environment or alias paths",
        checklist_text,
        flags=re.IGNORECASE,
    )
    cve_match = re.search(
        r"CVE-token audit is currently balanced:\s+(\d+)\s+unique Vulhub\s+CVE tokens",
        checklist_text,
        flags=re.IGNORECASE,
    )
    if scope_match is None:
        return ["Source Audit scope summary line was not found."]

    declared_roots, declared_readmes = (int(scope_match.group(1)), int(scope_match.group(2)))
    actual_roots = len(java_roots(vulhub_root))
    actual_readmes = len(java_readmes(vulhub_root))
    actual_cves = len(java_cve_tokens(vulhub_root))
    mismatches: list[str] = []
    if declared_roots != actual_roots:
        mismatches.append(f"Source Audit declares {declared_roots} Java roots, actual is {actual_roots}.")
    if declared_readmes != actual_readmes:
        mismatches.append(
            f"Source Audit declares {declared_readmes} Java/JVM README paths, actual is {actual_readmes}."
        )
    if cve_match is None:
        mismatches.append("Source Audit CVE-token summary line was not found.")
    else:
        declared_cves = int(cve_match.group(1))
        if declared_cves != actual_cves:
            mismatches.append(f"Source Audit declares {declared_cves} unique CVE tokens, actual is {actual_cves}.")
    return mismatches


def candidate_placeholder_errors(checklist: Path) -> list[str]:
    count = read_text(checklist).count(PLACEHOLDER)
    if count == 1:
        return []
    return [f"Expected exactly one candidate placeholder row, found {count}."]


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vulhub-root",
        default=None,
        help="Path to the local Vulhub checkout; defaults to VULHUB_ROOT or /tmp/vulhub-ohmyrasp-20260603.",
    )
    parser.add_argument("--checklist", type=Path, default=CHECKLIST, help="Coverage checklist path.")
    parser.add_argument("--algorithm-doc", type=Path, default=ALGORITHM_DOC, help="Algorithm coverage doc path.")
    parser.add_argument("--scripts-dir", type=Path, default=SCRIPTS, help="Directory containing acceptance scripts.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    fallback = "/tmp/vulhub-ohmyrasp-20260603"
    vulhub_root = Path(args.vulhub_root or os.environ.get("VULHUB_ROOT", fallback))
    if not vulhub_root.exists():
        print(f"Vulhub root does not exist: {vulhub_root}", file=sys.stderr)
        return 2
    if not args.checklist.exists():
        print(f"Checklist does not exist: {args.checklist}", file=sys.stderr)
        return 2
    if not args.algorithm_doc.exists():
        print(f"Algorithm doc does not exist: {args.algorithm_doc}", file=sys.stderr)
        return 2
    if not args.scripts_dir.exists():
        print(f"Scripts directory does not exist: {args.scripts_dir}", file=sys.stderr)
        return 2

    corpus = search_corpus(args.checklist, args.algorithm_doc, args.scripts_dir)
    readmes = java_readmes(vulhub_root)
    roots = java_roots(vulhub_root)
    cves = java_cve_tokens(vulhub_root)
    missing = missing_readme_mentions(vulhub_root, corpus)
    missing_cves = missing_cve_mentions(vulhub_root, corpus)
    weak = rows_without_evidence(args.checklist)
    audit_mismatches = source_audit_mismatches(vulhub_root, args.checklist)
    placeholder_errors = candidate_placeholder_errors(args.checklist)

    print(f"Vulhub root: {vulhub_root}")
    print(f"Checklist: {args.checklist}")
    print(f"Algorithm doc: {args.algorithm_doc}")
    print(f"Scripts dir: {args.scripts_dir}")
    print(f"Java/JVM roots: {len(roots)}")
    print(f"Java/JVM README paths: {len(readmes)}")
    print(f"Java/JVM CVE tokens: {len(cves)}")
    print(f"Unmentioned Java/JVM README paths: {len(missing)}")
    print(f"Unmentioned Java/JVM CVE tokens: {len(missing_cves)}")
    print(f"Covered target rows: {len(covered_target_rows(args.checklist))}")
    print(f"Covered rows without acceptance/boundary evidence: {len(weak)}")
    print(f"Source Audit count mismatches: {len(audit_mismatches)}")
    print(f"Candidate placeholder errors: {len(placeholder_errors)}")

    if missing:
        print("\nUnmentioned Java/JVM README paths:")
        for rel in missing:
            print(f"- {rel}")
    if missing_cves:
        print("\nUnmentioned Java/JVM CVE tokens:")
        for token in missing_cves:
            print(f"- {token}")
    if weak:
        print("\nCovered target rows without acceptance or boundary evidence:")
        for lineno, row in weak:
            print(f"- {display_path(args.checklist)}:{lineno}: {row}")
    if audit_mismatches:
        print("\nSource Audit count mismatches:")
        for error in audit_mismatches:
            print(f"- {error}")
    if placeholder_errors:
        print("\nCandidate placeholder errors:")
        for error in placeholder_errors:
            print(f"- {error}")

    return 1 if missing or missing_cves or weak or audit_mismatches or placeholder_errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
