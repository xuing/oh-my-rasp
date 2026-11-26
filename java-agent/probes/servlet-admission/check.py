"""Verify servlet-entry enforcement and ordinary callback delivery against packaged agents."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(COMMON))
import agent_track  # noqa: E402
from servlet_fixture import APIS, api_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--api-dir", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    track = agent_track.track(agent)
    fixture_name = "BackportServletAdmissionCheck" if track else "ServletAdmissionCheck"
    source = Path(__file__).with_name(fixture_name + ".java")
    for namespace in APIS:
        with tempfile.TemporaryDirectory() as work:
            api = api_jar(namespace, Path(work), args.api_dir)
            cp = os.pathsep.join(map(str, (work, api, agent)))
            fixture = Path(work) / source.name
            fixture.write_text(source.read_text().replace("import javax.servlet", f"import {namespace}.servlet"))
            subprocess.run(["javac", "-cp", cp, "-d", work, fixture], check=True)
            for mode in ("block", "monitor"):
                log = Path(work) / f"{mode}.jsonl"
                subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.control=none",
                                "-Dohmyrasp.standalone=true", f"-Dohmyrasp.mode={mode}", f"-Dohmyrasp.log={log}",
                                "-Dohmyrasp.log.sync=true", "-cp", cp, fixture_name, mode, *([str(track)] if track else [])], check=True)
                events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
                if track:
                    action = "block" if mode == "block" else "log"
                    reads = [e for e in events if e.get("algorithm") == f"java{track}_file_sensitive_read"]
                    if (len(reads) != 1 or reads[0]["action"] != action
                            or reads[0]["details"].get("decision_basis") != "request_selected_hosts"):
                        raise SystemExit(f"unexpected query-only file receipts: {reads}")
                    events = [e for e in events if e not in reads]
                    if not events or any(e.get("algorithm") != f"java{track}_request_internal_identity"
                                         or e["action"] != action or "/admin/reports" not in e["details"]["request"]
                                         for e in events):
                        raise SystemExit(f"unexpected {namespace} Java {track} {mode} receipts: {events}")
                    continue
                response_events = events[:2]
                expected_rules = ["response_dataLeak", "xss_echo"]
                evidence = [{"kind": "Bank Card"}, {"decision_basis": "verbatim_request_markup"}]
                if ([(e["algorithm"], e["action"]) for e in response_events] != [(rule, mode) for rule in expected_rules]
                        or [e["details"] for e in response_events] != evidence
                        or any(any(e["request"].values()) for e in response_events)):
                    raise SystemExit(f"unexpected {namespace} {mode} response policy receipts")
                events = events[2:]
                markup = events[:2]
                if [(e["algorithm"], e["action"]) for e in markup] != [("xss_userinput", "log"), ("xss_userinput", mode)]:
                    raise SystemExit(f"unexpected {namespace} {mode} input policy receipts: {markup}")
                events = events[2:]
                expected = [(mode, "/reports")] * 3 + [("log", "/reports"), ("log", "/error"),
                            ("log", "/reports"), ("log", "/reports")]
                if ([(e["action"], e["request"]["uri"]) for e in events] != expected
                        or any(e["algorithm"] != "request_scanner" for e in events)):
                    raise SystemExit(f"unexpected {namespace} {mode} receipts: {events}")


if __name__ == "__main__":
    main()
