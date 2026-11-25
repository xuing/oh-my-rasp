"""Inventory catalogue, ledger and retained event evidence without running a scenario."""

import hashlib
import json
import re
import tomllib
from collections import Counter
from pathlib import Path

SCRIPT = re.compile(r"\bacceptance-vulhub-[\w.-]+\.sh\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
LOG_DIR = re.compile(r"""\blogs/(vulhub-[\w.-]+-protected)(?=["'/\s])""")


def event_summary(path):
    decisions = Counter()
    invalid = 0
    records = 0
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                event = None
            if not isinstance(event, dict):
                invalid += 1
                continue
            records += 1
            key = tuple(event.get(field) for field in ("hook", "algorithm", "action"))
            if all(isinstance(value, str) for value in key) and event.get("kind") != "telemetry":
                details = event.get("details")
                basis = details.get("decision_basis") if isinstance(details, dict) else None
                decisions[(*key, basis if isinstance(basis, str) else "")] += 1
    return {
        "records": records,
        "invalid_records": invalid,
        "decisions": [
            dict(hook=hook, algorithm=algorithm, action=action, decision_basis=basis or None, count=count)
            for (hook, algorithm, action, basis), count in sorted(decisions.items())
        ],
    }


def build_report(root, java_roots, ledger_rows, scripts_dir, logs_dir):
    if not logs_dir.is_dir():
        raise ValueError(f"missing logs directory: {logs_dir}")
    with (root / "environments.toml").open("rb") as stream:
        catalog = tomllib.load(stream)["environment"]
    entries = {entry["path"]: entry for entry in catalog}
    if len(entries) != len(catalog):
        raise ValueError("duplicate environment paths in Vulhub catalogue")
    manifests = {p.parent.relative_to(root).as_posix() for name in
                 ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml")
                 for p in root.glob(f"*/*/{name}")}
    readmes = {p.parent.relative_to(root).as_posix() for p in root.glob("*/*/README.md")}

    logs = {p.relative_to(logs_dir).as_posix(): event_summary(p)
            for p in sorted(logs_dir.glob("vulhub-*/**/events.jsonl"))}
    scripts = {}
    paths_in_scripts = {}
    for script in sorted(scripts_dir.glob("acceptance-vulhub-*.sh")):
        text = script.read_text()
        # Match literal evidence references only. Dynamic shell variables and
        # version loops do not uniquely identify an individual environment.
        directories = sorted(set(LOG_DIR.findall(text)))
        scripts[script.name] = {
            "declared_protected_dirs": directories,
            "retained_event_files": [f"{d}/events.jsonl" for d in directories if f"{d}/events.jsonl" in logs],
        }
        for env in entries:
            if re.search(r"(?<![\w.-])" + re.escape(env) + r"(?![\w.-])", text):
                paths_in_scripts.setdefault(env, []).append(script.name)

    rows_by_cve = {}
    for number, row in ledger_rows:
        for cve in set(CVE.findall(row)):
            rows_by_cve.setdefault(cve.upper(), []).append({
                "line": number, "script_references": sorted(set(SCRIPT.findall(row)))})
    environments = []
    for path in sorted(entries.keys() | manifests | readmes):
        entry = entries.get(path, {})
        identifiers = entry.get("cve", [])
        references = {row["line"]: row for cve in identifiers for row in rows_by_cve.get(cve.upper(), [])}
        environments.append({
            "path": path, "catalogued": path in entries, "compose": path in manifests,
            "readme": path in readmes, "java_scope": path.partition("/")[0] in java_roots,
            "identifiers": identifiers, "catalog_tags": entry.get("tags", []),
            "exact_path_script_references": paths_in_scripts.get(path, []),
            "ledger_rows_sharing_identifier": [references[n] for n in sorted(references)],
        })
    digest = hashlib.sha256((root / "environments.toml").read_bytes()).hexdigest()
    return {"catalog_sha256": digest, "environments": environments, "scripts": scripts, "historical_logs": logs}


def write_report(destination: Path, **kwargs):
    report = build_report(**kwargs)
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    return report
