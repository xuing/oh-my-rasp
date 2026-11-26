#!/usr/bin/env python3
"""Check that an ordinary background pipeline starts under block mode without a detection."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    agent = parser.parse_args().agent.resolve(strict=True)
    source = Path(__file__).with_name("BackgroundProcessCheck.java")
    with tempfile.TemporaryDirectory(prefix="background-process-") as work:
        subprocess.run(["javac", "-d", work, source], check=True)
        log = Path(work) / "events.jsonl"
        log.touch()
        run = subprocess.run(["java", "-Dohmyrasp.standalone=true", "-Dohmyrasp.mode=block", "-Dohmyrasp.control=none",
                              f"-Dohmyrasp.log={log}", "-Dohmyrasp.log.sync=true", f"-javaagent:{agent}",
                              "-cp", work, "BackgroundProcessCheck"],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if run.returncode:
            raise SystemExit(run.stdout)
        events = [json.loads(line) for line in log.read_text().splitlines()]
        started = any(e.get("event", "").endswith("-agent-start") for e in events)
        if not started and "[OHMYRASP] agent started with ASM transformer" not in run.stdout:
            raise SystemExit("Agent startup record missing")
        if any(e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection" for e in events):
            raise SystemExit("Ordinary background job produced a detection")


if __name__ == "__main__":
    main()
