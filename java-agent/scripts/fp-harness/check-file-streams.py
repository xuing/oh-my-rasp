#!/usr/bin/env python3
"""Check host and ZIP stream-name semantics against the packaged primary agent."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    jar = parser.parse_args().agent.resolve(strict=True)
    source = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="stream-names-") as tmp:
        log = Path(tmp) / "events.jsonl"
        log.touch()
        subprocess.run(["javac", "-d", tmp, source / "HttpTransportCheck.java", source / "FileStreamNameCheck.java"], check=True)
        subprocess.run(["java", "-Xverify:all", f"-javaagent:{jar}", "-Djdk.io.File.enableADS=true",
                        "-Dohmyrasp.standalone=true", "-Dohmyrasp.mode=block", "-Dohmyrasp.force_block=true",
                        "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}", "-cp", tmp, "FileStreamNameCheck"], check=True,
                       timeout=45)
        events = [e for line in log.read_text(encoding="utf-8").splitlines() if (e := json.loads(line)).get("kind") == "detection"]
        decisions = [(e["algorithm"], e["action"], e["details"].get("stream")) for e in events]
        expected = [("writeFile_script", "block", None)]
        if os.name == "nt":
            expected.extend(("writeFile_NTFS", action, "author") for action in ("log", "block", "block"))
        if decisions != expected:
            raise SystemExit(f"unexpected stream policy decisions: {decisions}")


if __name__ == "__main__":
    main()
