#!/usr/bin/env python3
"""Verify local Spring initialization and the provenance of a process-init dispatch."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--jar-dir", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    track = agent_track.track(agent) or "main"
    libraries = args.jar_dir / ("modern" if track == "main" else "legacy")
    sources = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="spring-process-") as tmp:
        cp = os.pathsep.join([tmp, str(libraries / "*")])
        subprocess.run(["javac", "-cp", cp, "-d", tmp, COMMON / "HttpTransportCheck.java",
                        sources / "SpringProcessCheck.java"], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            p = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                f"-Dohmyrasp.log={log}", "-cp", cp, "SpringProcessCheck", track, mode],
                               text=True, capture_output=True, timeout=45)
            if p.returncode:
                raise SystemExit(p.stdout + p.stderr)
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
            rule = "command_spring_remote_init" if track == "main" else f"java{track}_command_execution_exploit_primitive"
            if (len(events) != 2 or any(e["algorithm"] != rule or (e["action"] == "block") != (mode == "block")
                                        or e["details"].get("decision_basis") != "remote_bean_init_dispatch" for e in events)):
                raise SystemExit(f"unexpected {track} Spring decisions in {mode}: {events}")


if __name__ == "__main__":
    main()
