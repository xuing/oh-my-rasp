#!/usr/bin/env python3
"""Check class-definition origin policy and local RMI resolution in packaged agents."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    jar = parser.parse_args().agent.resolve(strict=True)
    with zipfile.ZipFile(jar) as archive:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in archive.namelist()), "main")
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="rmi-codebase-") as tmp:
        subprocess.run(["javac", "-d", tmp, src / "HttpTransportCheck.java", src / "ClassDefinitionCheck.java", src / "RmiCodebaseCheck.java"], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{jar}", "-Dohmyrasp.standalone=true",
                                  "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                  f"-Dohmyrasp.log={log}", "-cp", tmp, "RmiCodebaseCheck", track, mode],
                                 capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
            rule = "classloader_remote" if track == "main" else f"java{track}_classloader_remote_codebase"
            transport = [e for e in events if e["algorithm"] != rule]
            if not transport or any("ssrf" not in e["algorithm"] or "/selected.jar" not in e["details"].get("url", "")
                                    or not e["details"].get("decision_basis", "").startswith("http_")
                                    or (e["action"] == "block") != (mode == "block") for e in transport):
                raise SystemExit(f"wrong archive HTTP decisions in {mode}: {transport}")
            observed = []
            for event in (e for e in events if e["algorithm"] == rule):
                if event["algorithm"] != rule or (event["action"] == "block") != (mode == "block"):
                    raise SystemExit(f"wrong policy decision in {mode}: {event}")
                details = event["details"]
                if details.get("decision_basis") != "url_class_definition":
                    raise SystemExit(f"wrong operation in {mode}: {event}")
                source = details["url"] if track == "main" else details["codebase"].split(" ", 2)[2]
                observed.append(urlsplit(source).path)
            if sorted(observed) != sorted(["/reports/fixture/reports/Weekly.class", "/report.jar", "/reports/weekly.txt"]):
                raise SystemExit(f"unexpected class origins in {mode}: {observed}")


if __name__ == "__main__":
    main()
