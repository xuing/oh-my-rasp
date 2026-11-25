#!/usr/bin/env python3
"""Fail when hand-written docs restate facts that drift as the code changes.

Docs keep one home per fact: a value that changes with releases or code (the
current release tag, a pinned toolchain or image version, a count of hooks or
scenarios, the list of release assets) lives in its source file or in a
generated document or region, and other docs link there. See AGENTS.md
"Documentation".

Checks, over tracked hand-written Markdown (CHANGELOG.md, docs/internal/, the
Vulhub evidence ledgers and the generator-owned files and regions listed below
are skipped):

  generated  every doc generator's --check passes; generated markers and
             banners appear only where a generator owns them
  release    no released tag (git tag -l 'v*') is written out
  pins       no image reference to a pinned image (any tag) and no version
             copied from a pin file (Dockerfile FROM, compose image:, go.mod,
             rust-toolchain.toml, Cargo.toml, ASM in build.gradle.kts,
             engines.node in package.json)
  counts     no code-base count (N hooks/scenarios/assets/...) outside a
             generated region, in prose or in a table
  assets     the docs/runbooks/release.md asset list equals the set of assets
             the release workflow publishes (and EXPECTED_ASSETS), and every
             ohmyrasp-* artifact a doc names is one the release workflow or a
             Gradle build produces
  links      relative Markdown links (inline and reference-style) resolve to
             tracked files, and a #fragment on a Markdown target names one of
             its headings (also checked in the evidence ledgers)

and over the evidence ledgers (LEDGERS), which need no Vulhub snapshot here:

  ledger     every acceptance script path they name is a tracked file; every
             "`<script>.sh` blocks `<id>`" claim names an id written in that
             script; every script under java-agent/acceptance/vulhub/ has a
             row in the Vulhub ledger

Usage: python3 scripts/check-docs.py
"""
from __future__ import annotations

import functools
import json
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "ohmyrasp-release.yml"
RELEASE_RUNBOOK = "docs/runbooks/release.md"

# Generator-owned outputs. A file or region counts as generated only if it is
# listed here, so a stray banner or marker cannot exempt hand-written text.
GENERATORS = {
    "java-agent/scripts/gen-detection-coverage.py": ["python3", "java-agent/scripts/gen-detection-coverage.py", "--check"],
    "deploy/shirudo/gen-readmes.py": ["python3", "deploy/shirudo/gen-readmes.py", "--check"],
}
GENERATED_FILES = {
    "java-agent/docs/DETECTION-COVERAGE.md",  # gen-detection-coverage.py
    "java-agent/docs/FALSE-POSITIVE-REPORT.md",  # run-fp-report.sh (needs Docker; not re-run here)
    "deploy/shirudo/README.md",  # gen-readmes.py
}
GENERATED_FILE_PATTERNS = [re.compile(r"deploy/shirudo/ohmyrasp-[a-z0-9]+/README\.md")]  # gen-readmes.py
GENERATED_REGIONS = {"metrics": ("README.md", "README.zh-CN.md")}  # gen-detection-coverage.py

VULHUB_LEDGER = "docs/development/vulhub-coverage.md"
LEDGERS = (VULHUB_LEDGER, "docs/development/algorithm-coverage.md")
SKIP_PREFIXES = ("docs/internal/",)
SKIP_FILES = {
    "CHANGELOG.md",  # history by design
    # The evidence ledgers record CVE ids, vulnerable target versions and the Source Audit counts that
    # java-agent/scripts/check-vulhub-java-coverage.py verifies against a Vulhub snapshot, so the
    # release, pins, counts and assets checks do not apply. The links and ledger checks do.
    *LEDGERS,
}

REGION = re.compile(r"<!-- BEGIN GENERATED (\S+).*?<!-- END GENERATED \1 -->", re.S)
MARKER = re.compile(r"<!-- (BEGIN|END) GENERATED (\S+)")
BANNER = re.compile(r"^>?\s*\**Generated\**\s+by\b", re.I)

NUMBER_WORDS = "two|three|four|five|six|seven|eight|nine|ten|eleven|twelve"
COUNT_NOUNS = (
    r"(?:ASM\s+)?hook\s+(?:modules?|famil(?:y|ies))|hooks|HookModule\s+(?:classes|implementations)"
    r"|(?:ASM\s+)?transformers?(?:\s+families)?|detector\s+capabilities|capabilities"
    r"|(?:verified\s+)?algorithm\s+signatures?|algorithms|scenarios?|Vulhub\s+roots|CVEs\s+tracked"
    r"|(?:release\s+)?assets|`?\.bee`?\s+packages|package\s+directories|standalone\s+JARs"
    r"|(?:benign\s+)?inputs|categories|Struts2\s+(?:OGNL\s+)?(?:advisories|scenarios)|alerts|paths"
)
# Up to two words (plain, hyphenated or `code`) may sit between the number and
# the noun: "54 `DetectorEngine` capabilities", "83 benign-but-plausible inputs".
COUNT_EN = re.compile(
    rf"(?<![\w.%/-])(?:\d+|{NUMBER_WORDS})(?:\s+(?:`[^`]+`|[A-Za-z][\w-]*)){{0,2}}?\s+(?:{COUNT_NOUNS})\b", re.I)
COUNT_EN_COMPOUND = re.compile(r"(?<![\w.%/-])\d+-scenario\b", re.I)
# CJK text runs straight into digits ("覆盖136个场景"), so only ASCII word
# characters block a match on the left.
COUNT_ZH = re.compile(
    r"(?<![A-Za-z0-9_.])\d+\s*(?:个|项|类|条)\s*(?:ASM\s*)?"
    r"(?:hook|transformer|场景|检测能力|算法|签名|组件根|CVE|Release\s*资产|资产|\.bee\s*包|包|告警|正常输入)"
)
COUNT_NOUN_CELL = re.compile(rf"(?:{COUNT_NOUNS})|场景|检测能力|算法签名|组件根", re.I)
NUMBER_CELL = re.compile(r"^[*_]*\d+[*_]*$")

ASSET_NAME = re.compile(r"ohmyrasp-[a-z0-9<>.*-]*?\.(?:jar|tar\.gz|tgz)")
VERSION_VAR = re.compile(
    r"\$\{\{\s*(?:steps|needs)\.release\.outputs\.version\s*\}\}|\$\{VERSION\}|\$VERSION\b")
INLINE_LINK = re.compile(r"\]\((?:<([^>\n]+)>|([^)\s]+))(?:\s+\"[^\"]*\")?\)")  # <a b.md> may hold spaces
REF_LINK = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?")
INLINE_CODE = re.compile(r"`[^`]*`")
FENCE = re.compile(r"^(```|~~~)")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$")
HTML_ANCHOR = re.compile(r"<a\s+(?:id|name)=\"([^\"]+)\"")

# An acceptance script as the ledgers name it: relative to java-agent/ or to the repo root.
SCRIPT_PATH = re.compile(r"(?<![\w/.<-])(?:java-agent/)?(acceptance/[\w./-]+\.sh)\b")
# "`acceptance/x.sh` blocks `rule_id`": the first code span after "block(s)", within one clause.
BLOCKS_CLAIM = re.compile(r"\bblocks?\b[^`;]{0,100}?`([A-Za-z]\w*)`")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def tracked(*patterns: str) -> list[str]:
    return [p for p in git("ls-files", "-z", *patterns).split("\0") if p]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n")


def is_generated_file(rel: str) -> bool:
    return rel in GENERATED_FILES or any(p.fullmatch(rel) for p in GENERATED_FILE_PATTERNS)


def doc_files() -> list[str]:
    return [
        rel for rel in tracked("*.md")
        if rel not in SKIP_FILES and not rel.startswith(SKIP_PREFIXES)
        and "/node_modules/" not in rel and not is_generated_file(rel)
    ]


def visible_lines(rel: str) -> list[tuple[int, str]]:
    """(line number, text) with owned generated regions blanked out."""
    text = REGION.sub(
        lambda m: "\n" * m.group(0).count("\n") if rel in GENERATED_REGIONS.get(m.group(1), ()) else m.group(0),
        read(rel),
    )
    return list(enumerate(text.split("\n"), start=1))


def token(value: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w.-]){re.escape(value)}(?![\w-]|\.\d)")


# --- sources of truth ---------------------------------------------------------

def release_tags() -> list[str]:
    tags = git("tag", "-l", "v*").split()
    return sorted({t for tag in tags for t in (tag, tag[1:])}, key=len, reverse=True)


def pins() -> tuple[dict[str, str], dict[str, str]]:
    """(pinned image name -> owner, copy-prone pinned value -> owner)."""
    images: dict[str, str] = {}
    values: dict[str, str] = {}

    def add_image(ref: str, owner: str) -> None:
        ref = ref.split("@sha256:")[0]
        if "$" in ref or ref.startswith(("ohmyrasp/", "ghcr.io/xuing/")) or ":" not in ref:
            return
        name, _, tag = ref.rpartition(":")
        images.setdefault(name, owner)
        values.setdefault(ref, owner)
        version = re.match(r"v?(\d+(?:\.\d+){1,3})", tag)
        if version:
            values.setdefault(version.group(1), owner)

    for rel in tracked("*Dockerfile*"):
        for m in re.finditer(r"^FROM\s+(?:--\S+\s+)*(\S+)", read(rel), re.M):
            add_image(m.group(1), rel)
    for rel in tracked("*docker-compose*.yml", "*docker-compose*.yaml"):
        for m in re.finditer(r"^\s*image:\s*[\"']?([^\s\"']+)", read(rel), re.M):
            add_image(m.group(1), rel)
    for rel in tracked("*go.mod"):
        for m in re.finditer(r"^(?:go|toolchain)\s+(?:go)?(\d+\.\d+\.\d+)", read(rel), re.M):
            values.setdefault(m.group(1), rel)
    for rel in tracked("*rust-toolchain.toml", "*Cargo.toml"):
        for m in re.finditer(r"^(?:channel|rust-version)\s*=\s*\"(\d+\.\d+\.\d+)\"", read(rel), re.M):
            values.setdefault(m.group(1), rel)
    for rel in tracked("*build.gradle.kts"):
        for m in re.finditer(r"org\.ow2\.asm:asm(?:-commons)?:(\d+\.\d+\.\d+)", read(rel)):
            values.setdefault(m.group(1), rel)
    for rel in tracked("*package.json"):
        if "/node_modules/" in rel:
            continue
        node = json.loads(read(rel)).get("engines", {}).get("node")
        if node:
            values.setdefault(node, rel)
    return images, values


def gradle_archives() -> set[str]:
    """Jar names set by archiveBaseName in Gradle builds (e.g. the thin jar)."""
    names: set[str] = set()
    for rel in tracked("*build.gradle.kts"):
        names.update(f"{base}.jar" for base in re.findall(r'archiveBaseName\.set\("([^"]+)"\)', read(rel)))
    return names


def release_workflow() -> tuple[set[str], set[str], int]:
    """(artifact names the workflow produces, the published asset set, EXPECTED_ASSETS)."""
    text = VERSION_VAR.sub("<version>", RELEASE_WORKFLOW.read_text(encoding="utf-8"))
    expected = re.search(r"EXPECTED_ASSETS:\s*(\d+)", text)
    if not expected:
        raise SystemExit(f"{RELEASE_WORKFLOW}: EXPECTED_ASSETS not found")
    produced = {n for n in ASSET_NAME.findall(text) if "*" not in n}
    # The assemble step copies every staged artifact into dist/, renaming some:
    #   if [[ "$base" == "<from>" ]]; then
    #     cp "$f" "dist/<to>"
    renames = dict(re.findall(r'"\$base"\s*==\s*"([^"]+)"\s*\]\];\s*then\s*\n\s*cp\s+"\$f"\s+"dist/([^"]+)"', text))
    if not renames:
        raise SystemExit(f"{RELEASE_WORKFLOW}: the assemble step's rename rule was not found")
    published = {renames.get(n, n) for n in produced} | {"SHA256SUMS.txt"}
    return produced | set(renames.values()), published, int(expected.group(1))


# --- checks -------------------------------------------------------------------

def check_generated(problems: list[str]) -> None:
    for cmd in GENERATORS.values():
        run = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if run.returncode:
            problems.append(f"generated: `{' '.join(cmd)}` failed:\n    {(run.stderr or run.stdout).strip()}")
    for rel in tracked("*.md"):
        if "/node_modules/" in rel:
            continue
        lines = read(rel).split("\n")
        if not is_generated_file(rel) and any(BANNER.match(line) for line in lines[:8]):
            problems.append(f"generated: {rel}: has a 'Generated by' banner but no generator owns it in scripts/check-docs.py")
        open_slug = None
        for no, line in enumerate(lines, start=1):
            for kind, slug in MARKER.findall(INLINE_CODE.sub("", line)):  # `<!-- ... -->` in code is an example
                if rel not in GENERATED_REGIONS.get(slug, ()):
                    problems.append(f"generated: {rel}:{no}: region '{slug}' is not owned by any generator")
                elif kind == "BEGIN":
                    if open_slug:
                        problems.append(f"generated: {rel}:{no}: region '{slug}' opens inside '{open_slug}'")
                    open_slug = slug
                elif open_slug != slug:
                    problems.append(f"generated: {rel}:{no}: region '{slug}' ends before it begins")
                else:
                    open_slug = None
        if open_slug:
            problems.append(f"generated: {rel}: region '{open_slug}' is never closed")


def table_count(line: str) -> str | None:
    """A table row that pairs a count noun with a bare number cell."""
    if not line.lstrip().startswith("|"):
        return None
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if any(NUMBER_CELL.match(c) for c in cells) and any(COUNT_NOUN_CELL.search(c) for c in cells):
        return line.strip()
    return None


def check_lines(files: list[str], problems: list[str]) -> None:
    tags = [(t, token(t)) for t in release_tags()]
    images, values = pins()
    image_pats = [(name, owner, re.compile(rf"(?<![\w./-]){re.escape(name)}:[\w.${{}}-]+"))
                  for name, owner in images.items()]
    value_pats = [(v, owner, token(v)) for v, owner in sorted(values.items(), key=lambda kv: -len(kv[0]))]
    produced, _, _ = release_workflow()
    built = gradle_archives()

    for rel in files:
        for no, line in visible_lines(rel):
            where = f"{rel}:{no}"
            for tag, pat in tags:
                if pat.search(line):
                    problems.append(f"release: {where}: names release `{tag}`; use `<version>` or link GitHub Releases")
                    break
            pin_hit = next(((f"{name}:<tag>", owner) for name, owner, pat in image_pats if pat.search(line)), None)
            pin_hit = pin_hit or next(((v, owner) for v, owner, pat in value_pats if pat.search(line)), None)
            if pin_hit:
                problems.append(f"pins: {where}: copies `{pin_hit[0]}` pinned in {pin_hit[1]}; refer to that file instead")
            plain = line.replace("**", "").replace("__", "")
            count = next((m.group(0) for p in (COUNT_EN, COUNT_EN_COMPOUND, COUNT_ZH) for m in [p.search(plain)] if m),
                         None) or table_count(plain)
            if count:
                problems.append(
                    f"counts: {where}: hand-written count `{count}`; link the generated report or use a generated region")
            for name in set(ASSET_NAME.findall(VERSION_VAR.sub("<version>", line))):
                if "<" in name.replace("<version>", "") or "*" in name:
                    continue  # a pattern such as ohmyrasp-<track>.jar
                if name not in produced and name not in built:
                    problems.append(
                        f"assets: {where}: `{name}` is produced by neither"
                        f" {RELEASE_WORKFLOW.relative_to(ROOT)} nor a Gradle build")


def heading_anchors(text: str) -> set[str]:
    """The #fragments GitHub gives a Markdown file: heading slugs (-1, -2 for repeats) and <a id>/<a name>."""
    anchors: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    for line in text.split("\n"):
        if FENCE.match(line.strip()):
            in_fence = not in_fence
        if in_fence:
            continue
        anchors.update(a.lower() for a in HTML_ANCHOR.findall(line))
        heading = HEADING.match(line)
        if not heading:
            continue
        title = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading.group(1))  # a link keeps its text
        slug = re.sub(r"[^\w\- ]", "", re.sub(r"<[^>]+>", "", title).lower()).replace(" ", "-")
        repeat = seen.get(slug, 0)
        seen[slug] = repeat + 1
        anchors.add(f"{slug}-{repeat}" if repeat else slug)
    return anchors


@functools.cache
def anchors_of(rel: str) -> set[str]:
    return heading_anchors(read(rel))


def check_links(files: list[str], problems: list[str]) -> None:
    tracked_paths = set(tracked())
    tracked_dirs = {str(p) for f in tracked_paths for p in Path(f).parents}
    for rel in files:
        in_fence = False
        for no, line in visible_lines(rel):
            if FENCE.match(line.strip()):
                in_fence = not in_fence
            if in_fence:
                continue
            where = f"{rel}:{no}"
            for m in [*INLINE_LINK.finditer(INLINE_CODE.sub("", line)), *REF_LINK.finditer(line)]:
                target = next(g for g in m.groups() if g)
                if re.match(r"[a-z][a-z0-9+.-]*:", target):
                    continue
                path, _, fragment = target.split("?", 1)[0].partition("#")
                norm: str | None = rel
                if path:
                    try:
                        norm = str(((ROOT / rel).parent / path).resolve().relative_to(ROOT.resolve()))
                    except ValueError:
                        norm = None
                    if norm not in tracked_paths and norm not in tracked_dirs:
                        problems.append(f"links: {where}: `{target}` does not resolve to a tracked file")
                        continue
                if fragment and norm and norm.endswith(".md") and norm in tracked_paths \
                        and urllib.parse.unquote(fragment).lower() not in anchors_of(norm):
                    problems.append(f"links: {where}: `{target}`: {norm} has no heading with anchor `#{fragment}`")


# --- evidence ledgers ---------------------------------------------------------

def script_mentions(line: str) -> list[tuple[int, str]]:
    """(end offset, path relative to java-agent/) of each acceptance script the line names."""
    return [(m.end(), m.group(1)) for m in SCRIPT_PATH.finditer(line)]


def ledger_line_problems(where: str, line: str, script_text) -> list[str]:
    """Problems on one ledger line. script_text(path) is the script's text, or None if it is not tracked.

    A "blocks `X`" claim belongs to the nearest script named before it on the line, and X must be
    written in that script: as the expected algorithm, or as the argument a helper checks.
    """
    problems = []
    mentions = script_mentions(line)
    for _, path in mentions:
        if script_text(path) is None:
            problems.append(f"ledger: {where}: `{path}` is not a tracked script under java-agent/")
    for claim in BLOCKS_CLAIM.finditer(line):
        before = [path for end, path in mentions if end <= claim.start()]
        if not before or (text := script_text(before[-1])) is None:
            continue
        rule = claim.group(1)
        if not re.search(rf"(?<!\w){re.escape(rule)}(?!\w)", text):
            problems.append(
                f"ledger: {where}: `{before[-1]}` never names `{rule}`; say what the script asserts")
    return problems


def unreferenced_scripts(ledger: str, scripts: list[str]) -> list[str]:
    """Scripts (relative to java-agent/) that the ledger text never names."""
    named = {path for line in ledger.split("\n") for _, path in script_mentions(line)}
    return sorted(set(scripts) - named)


def check_ledgers(problems: list[str]) -> None:
    scripts = {p.removeprefix("java-agent/") for p in tracked("java-agent/acceptance") if p.endswith(".sh")}

    @functools.cache
    def script_text(path: str) -> str | None:
        return read(f"java-agent/{path}") if path in scripts else None

    for rel in LEDGERS:
        for no, line in enumerate(read(rel).split("\n"), start=1):
            problems.extend(ledger_line_problems(f"{rel}:{no}", line, script_text))
    for path in unreferenced_scripts(read(VULHUB_LEDGER), [p for p in scripts if p.startswith("acceptance/vulhub/")]):
        problems.append(f"ledger: java-agent/{path} has no row in {VULHUB_LEDGER}")


def check_release_runbook(problems: list[str]) -> None:
    _, published, expected = release_workflow()
    text = read(RELEASE_RUNBOOK)
    section = re.search(r"(\*\*GitHub Release assets[^\n]*)\n+(.*?)(?:\n[ \t]*\n|\Z)", text, re.S)
    if not section:
        problems.append(f"assets: {RELEASE_RUNBOOK}: '**GitHub Release assets**' list not found")
        return
    if re.search(r"\d", section.group(1)):
        problems.append(f"assets: {RELEASE_RUNBOOK}: the asset list heading states a count; EXPECTED_ASSETS owns it")
    listed = re.findall(r"`((?:ohmyrasp-|SHA256SUMS)[^`]*)`", section.group(2))
    dupes = sorted({n for n in listed if listed.count(n) > 1})
    if dupes:
        problems.append(f"assets: {RELEASE_RUNBOOK}: lists {', '.join(dupes)} more than once")
    for name in sorted(set(listed) - published):
        problems.append(f"assets: {RELEASE_RUNBOOK}: `{name}` is not a published release asset")
    for name in sorted(published - set(listed)):
        problems.append(f"assets: {RELEASE_RUNBOOK}: published asset `{name}` is missing from the list")
    if len(published) != expected:
        problems.append(
            f"assets: {RELEASE_WORKFLOW.relative_to(ROOT)} publishes {len(published)} assets"
            f" but sets EXPECTED_ASSETS={expected}")


def main() -> int:
    problems: list[str] = []
    files = doc_files()
    check_generated(problems)
    check_lines(files, problems)
    check_links([*files, *LEDGERS], problems)
    check_ledgers(problems)
    check_release_runbook(problems)
    if not release_tags():
        print("check-docs: warning: no v* tags found (shallow clone?); release check skipped", file=sys.stderr)
    for p in problems:
        print(p)
    if problems:
        print(f"\ncheck-docs: {len(problems)} problem(s) in {len(files)} docs. See AGENTS.md \"Documentation\".",
              file=sys.stderr)
        return 1
    print(f"check-docs: {len(files)} docs OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
