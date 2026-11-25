#!/usr/bin/env python3
"""Exercise Hadoop REST submission admission with a local client that only records calls."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--jar-dir", required=True, type=Path, help="directory created by the stageYarnProbe Gradle task")
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    jars = sorted(args.jar_dir.glob("*.jar"), key=lambda path: (not path.name.startswith("javax.servlet-api-"), path.name))
    if not jars:
        parser.error("no YARN fixture libraries found")
    with zipfile.ZipFile(agent) as jar:
        prefix = next((f"java{v}_" for v in ("8", "11", "17") if
                       f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "")
    with tempfile.TemporaryDirectory(prefix="yarn-submit-") as tmp:
        cp = os.pathsep.join((tmp, *map(str, jars)))
        source = Path(__file__).with_name("YarnReleaseSubmitCheck.java")
        subprocess.run(["javac", "-cp", cp, "-d", tmp, source], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                  "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", f"-Dohmyrasp.log={log}",
                                  "-Dohmyrasp.log.sync=true", "-cp", cp,
                                  "org.apache.hadoop.yarn.server.resourcemanager.webapp.YarnReleaseSubmitCheck", mode],
                                 capture_output=True, text=True, timeout=60)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            events = [e for e in rows if e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection"]
            if len(events) != 2 or any(e["algorithm"] != prefix + "request_remote_job_submission"
                    or e["details"].get("decision_basis") != "required_submit_role_denied"
                    or (e["action"] == "block") != (mode == "block") or "reports.Weekly" in json.dumps(e)
                    for e in events):
                raise SystemExit(f"incorrect YARN role evidence in {mode}")


if __name__ == "__main__":
    main()
