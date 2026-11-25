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
from urllib.request import urlopen
import zipfile

APIS = {
    "javax": ("javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar",
              "af456b2dd41c4e82cf54f3e743bc678973d9fe35bd4d3071fa05c7e5333b8482"),
    "jakarta": ("jakarta/servlet/jakarta.servlet-api/5.0.0/jakarta.servlet-api-5.0.0.jar",
                "33d3a5bda82c7d2f1b898685faa954f1fc34f7b0ae5c2f6ccc6d051e8a10973b"),
}


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
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    with tempfile.TemporaryDirectory(prefix="multipart-check-") as tmp:
        for namespace, (artifact, sha) in APIS.items():
            classes = Path(tmp) / namespace
            classes.mkdir()
            api = (args.api_dir or classes) / Path(artifact).name
            if args.api_dir is None:
                with urlopen("https://repo.maven.apache.org/maven2/" + artifact, timeout=25) as response:
                    api.write_bytes(response.read(512 * 1024))
            if hashlib.sha256(api.read_bytes()).hexdigest() != sha:
                raise SystemExit(f"wrong {namespace} API digest")
            check = classes / "MultipartAccessCheck.java"
            check.write_text((source / check.name).read_text().replace("import javax.servlet", f"import {namespace}.servlet"))
            subprocess.run(["javac", "-cp", api.resolve(), "-d", classes, source / "HttpTransportCheck.java", source / "MultipartIsolationCheck.java", check], check=True)
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
