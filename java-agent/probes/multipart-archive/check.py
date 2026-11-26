#!/usr/bin/env python3
"""Verify archive authorization using real Servlet APIs and inert attachment names."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import os
import subprocess
import tempfile
import sys

COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(COMMON))
import agent_track  # noqa: E402
from servlet_fixture import APIS, api_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--api-dir", type=Path, help="Use the pinned API jars from a local directory")
    parser.add_argument("--rounds", type=int, default=1, help="Repetitions of each access and isolation scenario")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    agent = args.agent.resolve(strict=True)
    source = Path(__file__).parent
    track = agent_track.track(agent) or "main"
    with tempfile.TemporaryDirectory(prefix="multipart-check-") as tmp:
        for namespace in APIS:
            classes = Path(tmp) / namespace
            classes.mkdir()
            api = api_jar(namespace, classes, args.api_dir)
            check = classes / "MultipartAccessCheck.java"
            check.write_text((source / check.name).read_text().replace("import javax.servlet", f"import {namespace}.servlet"))
            subprocess.run(["javac", "-cp", api.resolve(), "-d", classes, COMMON / "HttpTransportCheck.java", source / "MultipartIsolationCheck.java", check], check=True)
            cp = os.pathsep.join(map(str, (classes, api.resolve())))
            key = b"ohmyrasp.archiveUpload.POST/import\x00"
            expected = {hashlib.sha256(key + p).hexdigest(): n for p, n in [(b"role:operator", args.rounds), (b"deny", 6 * args.rounds)]}
            for probe in ("MultipartAccessCheck", "MultipartIsolationCheck"):
                counts = expected if probe == "MultipartAccessCheck" else {hashlib.sha256(key + b"role:operator").hexdigest(): 4 * args.rounds}
                for mode in ("block", "monitor"):
                    log = classes / (probe + "-" + mode + ".jsonl")
                    run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                          f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                                          "-cp", cp, probe, track, mode, str(args.rounds)],
                                         text=True, capture_output=True, timeout=55)
                    if run.returncode:
                        raise SystemExit(run.stdout + run.stderr)
                    events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("kind") == "detection"
                              or e.get("event") == "ohmyrasp-detection"]
                    if (Counter(e["details"].get("archive_policy_sha256") for e in events) != counts
                            or any(e["algorithm"] != "fileUpload_java_archive"
                                   or e["details"].get("multipart_source") != "active_request_lookup"
                                   or (e["action"] == "block") != (mode == "block") for e in events)):
                        raise SystemExit(f"unexpected {namespace} multipart decisions in {mode}")


if __name__ == "__main__":
    main()
