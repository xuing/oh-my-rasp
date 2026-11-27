#!/usr/bin/env python3
"""Check host write decisions against ZIP members and descriptor-relative Linux opens."""
import argparse
import json
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
    jar = parser.parse_args().agent.resolve(strict=True)
    track = agent_track.track(jar) or "main"
    source = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="write-namespace-") as tmp:
        subprocess.run(["javac", "-d", tmp, COMMON / "HttpTransportCheck.java", source / "WriteNamespaceCheck.java"], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            log.touch()
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{jar}", "-Dohmyrasp.standalone=true",
                                  f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                                  "-cp", tmp, "WriteNamespaceCheck", track, mode], text=True, capture_output=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            validate(run.stdout, log.read_bytes(), track, mode)


def validate(stdout, log, track, mode):
    file_rule = "writeFile_script" if track == "main" else f"java{track}_file_script_write"
    archive_rule = "archive_traversal" if track == "main" else f"java{track}_archive_entry_traversal_write"
    expected = {"zip-bytes": None, "zip-copy": None, "virtual-member": None, "old-directory": None,
                "host-bytes": (file_rule, None), "host-replace": (file_rule, None), "host-channel": (archive_rule, "archive_channel_open"),
                "bound-directory": (archive_rule, "archive_descriptor_open")}
    if track == "main":
        expected.update({"missing-lookup": None, "closed-reader": None, "closed-during-nested-request": None,
                         "resolved-lookup": (archive_rule, "archive_channel_open")})
        expected["host-generated-bytes"] = ("writeFile_generated_script", None)
        expected.update(dict.fromkeys(("zip-generated-bytes", "zip-generated-text", "zip-generated-lines")))
    action = "block" if mode == "block" else "log"
    def detections(data):
        return [e for line in data.splitlines() if (e := json.loads(line)).get("kind", e.get("event"))
                in ("detection", "ohmyrasp-detection")]
    total = 0
    for line in stdout.splitlines():
        if not line.startswith("row,"):
            continue
        _, case, denied, start, end = line.split(",")
        finding = expected.pop(case)
        events = detections(log[int(start):int(end)])
        total += len(events)
        if ((denied == "true") != (finding is not None and mode == "block") or
                bool(events) != bool(finding) or any(e["algorithm"] != finding[0] or e["action"] != action for e in events)):
            raise SystemExit(f"incorrect {mode} decisions for {case}")
        if finding and finding[1] and (len(events) != 1 or events[0]["details"].get("decision_basis") != finding[1]):
            raise SystemExit(f"incorrect write-open evidence for {case}")
    if expected or len(detections(log)) != total:
        raise SystemExit(f"incomplete receipts or detections outside the tested calls in {mode}")


if __name__ == "__main__":
    main()
