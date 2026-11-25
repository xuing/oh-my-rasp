"""Verify servlet-entry enforcement and ordinary callback delivery against packaged agents."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

from servlet_fixture import APIS, api_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--api-dir", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    with zipfile.ZipFile(agent) as archive:
        track = next((v for v in (8, 11, 17) if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in archive.namelist()), None)
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
                                "-Dohmyrasp.log.sync=true", "-cp", cp, fixture_name, mode], check=True)
                events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
                if track:
                    action = "block" if mode == "block" else "log"
                    if not events or any(e.get("algorithm") != f"java{track}_request_internal_identity"
                                         or e["action"] != action or "/admin/reports" not in e["details"]["request"]
                                         for e in events):
                        raise SystemExit(f"unexpected {namespace} Java {track} {mode} receipts: {events}")
                    continue
                expected = [(mode, "/reports"), (mode, "/reports"), ("log", "/reports"), ("log", "/error"),
                            ("log", "/reports"), ("log", "/reports")]
                if ([(e["action"], e["request"]["uri"]) for e in events] != expected
                        or any(e["algorithm"] != "request_scanner" for e in events)):
                    raise SystemExit(f"unexpected {namespace} {mode} receipts: {events}")


if __name__ == "__main__":
    main()
