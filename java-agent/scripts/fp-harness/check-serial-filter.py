#!/usr/bin/env python3
"""Verify stream filter selection and JDK rejection receipts with the packaged primary agent."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    jar = parser.parse_args().agent.resolve(strict=True)
    src = Path(__file__).parent
    marker = src.parents[1] / "playground/src/main/java/io/ohmyrasp/playground/EvilSerialized.java"
    with tempfile.TemporaryDirectory(prefix="serial-filter-") as work:
        subprocess.run(["javac", "-d", work, src / "SerialFilterCheck.java", src / "HttpTransportCheck.java", marker], check=True)
        for mode in ("block", "monitor"):
            for setup in ("plain", "global", "stream", "factory", "startup"):
                log = Path(work) / f"{setup}-{mode}.jsonl"
                startup = ["-Djdk.serialFilter=!SerialFilterCheck$Report;*"] if setup == "startup" else []
                run = subprocess.run(["java", "-Xverify:all", *startup, f"-javaagent:{jar}", "-Dohmyrasp.standalone=true",
                                      "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                      f"-Dohmyrasp.log={log}", "-cp", work, "SerialFilterCheck", setup, mode],
                                     capture_output=True, text=True, timeout=30)
                if run.returncode:
                    raise SystemExit(f"{setup} / {mode}\n" + run.stdout + run.stderr)
                rows = [json.loads(line) for line in log.read_text().splitlines()]
                events = [e for e in rows if e.get("kind") == "detection"]
                expected = ["/reports/marker"]
                if setup == "stream":
                    expected.extend(["/reports/element", "/reports/nested-element"])
                observed = [e["request"]["uri"] for e in events]
                if sorted(observed) != sorted(expected) or any(e["algorithm"] != "deserialization_blacklist"
                        or e["details"].get("class") != "io.ohmyrasp.playground.EvilSerialized"
                        or (e["action"] == "block") != (mode == "block") for e in events):
                    raise SystemExit(f"unexpected serial filter evidence for {setup} / {mode}")


if __name__ == "__main__":
    main()
