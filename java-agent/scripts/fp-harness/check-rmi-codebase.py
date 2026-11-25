#!/usr/bin/env python3
"""Check local RMI resolution and URL-classpath policy in packaged agents."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    jar = parser.parse_args().agent.resolve(strict=True)
    with zipfile.ZipFile(jar) as archive:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in archive.namelist()), "main")
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="rmi-codebase-") as tmp:
        subprocess.run(["javac", "-d", tmp, src / "HttpTransportCheck.java", src / "RmiCodebaseCheck.java"], check=True)
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
            if len(events) != 1 or events[0]["algorithm"] != rule or (events[0]["action"] == "block") != (mode == "block"):
                raise SystemExit(f"unexpected codebase decisions in {mode}: {events}")
            if events[0]["details"].get("decision_basis") != "classloader_url_configuration":
                raise SystemExit(f"wrong operation in {mode}: {events}")


if __name__ == "__main__":
    main()
