#!/usr/bin/env python3
"""Verify class allocation, factory fallback and cached deserializers using in-memory report records."""
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
    parser.add_argument("--jar-dir", required=True, type=Path)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="hessian-alloc-") as tmp:
        cp = os.pathsep.join((tmp, str(args.jar_dir / "*")))
        subprocess.run(["javac", "-d", tmp, src / "HessianAllocationCheck.java", src / "HttpTransportCheck.java",
                        src / "stream-types/listed/BeanComparator.java", src / "stream-types/BshMonthly.java", src / "stream-types/reports/BeanComparator.java"], check=True)
        for pkg in ("com.caucho.hessian.io", "com.alibaba.com.caucho.hessian.io"):
            for mode in ("block", "monitor"):
                log = Path(tmp) / f"{pkg}-{mode}.jsonl"
                run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                      "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                      f"-Dohmyrasp.log={log}", "-cp", cp, "HessianAllocationCheck", pkg, mode],
                                     text=True, capture_output=True, timeout=45)
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
                rule = "deserialization_hessian_type" if track == "main" else f"java{track}_deserialization_hessian_type"
                if len(events) != 2 or any(e["algorithm"] != rule or (e["action"] == "block") != (mode == "block")
                                          or e["details"].get("class") != "HessianAllocationCheck$Monthly"
                                          or e["details"].get("decision_basis") not in ("hessian_constructor", "hessian_unsafe_allocation") for e in events):
                    raise SystemExit(f"unexpected {pkg} allocation decisions in {mode}: {events}")


if __name__ == "__main__":
    main()
