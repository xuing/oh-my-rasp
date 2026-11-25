#!/usr/bin/env python3
"""Verify stream filter selection and JDK rejection receipts with the packaged primary agent."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from collections import Counter


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--c3p0-dir", type=Path, help="include real c3p0 library values in the plain filter check")
    args = parser.parse_args()
    jar = args.agent.resolve(strict=True)
    src = Path(__file__).parent
    marker = src.parents[1] / "playground/src/main/java/io/ohmyrasp/playground/EvilSerialized.java"
    with tempfile.TemporaryDirectory(prefix="serial-filter-") as work:
        subprocess.run(["javac", "-d", work, src / "SerialFilterCheck.java", src / "HttpTransportCheck.java", marker], check=True)
        for mode in ("block", "monitor"):
            for setup in ("plain", "global", "stream", "factory", "startup"):
                log = Path(work) / f"{setup}-{mode}.jsonl"
                startup = ["-Djdk.serialFilter=!SerialFilterCheck$Report;*"] if setup == "startup" else []
                c3p0 = args.c3p0_dir if setup == "plain" else None
                classpath = os.pathsep.join((work, str(c3p0 / "*"))) if c3p0 else work
                run = subprocess.run(["java", "-Xverify:all", *startup, f"-javaagent:{jar}", "-Dohmyrasp.standalone=true",
                                      "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                      f"-Dohmyrasp.log={log}", "-cp", classpath, "SerialFilterCheck", setup, mode,
                                      *(["c3p0"] if c3p0 else [])],
                                     capture_output=True, text=True, timeout=30)
                if run.returncode:
                    raise SystemExit(f"{setup} / {mode}\n" + run.stdout + run.stderr)
                rows = [json.loads(line) for line in log.read_text().splitlines()]
                events = [e for e in rows if e.get("kind") == "detection"]
                marker_details = ("deserialization_blacklist", "io.ohmyrasp.playground.EvilSerialized")
                expected = [("/reports/marker", *marker_details)]
                if setup == "stream":
                    expected.extend((uri, *marker_details) for uri in ("/reports/element", "/reports/nested-element"))
                if c3p0:
                    uri = "/reports/c3p0-pool-type"
                    expected.append((uri, "deserialization_gadget", "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"))
                    if mode == "monitor":
                        expected.append((uri, "deserialization_gadget",
                                         "com.mchange.v2.c3p0.impl.WrapperConnectionPoolDataSourceBase"))
                observed = [(e["request"]["uri"], e["algorithm"], e["details"].get("class")) for e in events]
                if Counter(observed) != Counter(expected) or any(
                    (e["action"] == "block") != (mode == "block") for e in events
                ):
                    raise SystemExit(f"unexpected serial filter evidence for {setup} / {mode}: {observed}")


if __name__ == "__main__":
    main()
