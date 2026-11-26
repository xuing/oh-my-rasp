#!/usr/bin/env python3
"""Verify class allocation, factory fallback and cached deserializers using in-memory report records."""
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
    parser.add_argument("--jar-dir", required=True, type=Path)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    track = agent_track.track(agent) or "main"
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="hessian-alloc-") as tmp:
        cp = os.pathsep.join((tmp, str(args.jar_dir / "*")))
        subprocess.run(["javac", "-cp", cp, "-d", tmp, src / "HessianAllocationCheck.java", COMMON / "HttpTransportCheck.java",
                        COMMON / "stream-types/listed/BeanComparator.java", COMMON / "stream-types/BshMonthly.java",
                        COMMON / "stream-types/reports/BeanComparator.java"], check=True)
        for codec in ("caucho", "dubbo"):
            for mode in ("block", "monitor"):
                log = Path(tmp) / f"{codec}-{mode}.jsonl"
                run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                      "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                      f"-Dohmyrasp.log={log}", "-cp", cp, "HessianAllocationCheck", codec, mode],
                                     text=True, capture_output=True, timeout=45)
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
                rule = "deserialization_hessian_type" if track == "main" else f"java{track}_deserialization_hessian_type"
                if len(events) != 2 or any(e["algorithm"] != rule or (e["action"] == "block") != (mode == "block")
                                          or e["details"].get("class") != "HessianAllocationCheck$Monthly"
                                          or e["details"].get("decision_basis") not in ("hessian_constructor", "hessian_unsafe_allocation") for e in events):
                    raise SystemExit(f"unexpected {codec} allocation decisions in {mode}: {events}")


if __name__ == "__main__":
    main()
