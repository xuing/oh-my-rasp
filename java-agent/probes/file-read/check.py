#!/usr/bin/env python3
"""Check file-read, directory-list and delete decisions from the packaged agent on the Linux compatibility matrix."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

COMMON = Path(__file__).resolve().parent.parent / "common"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--delete-only", action="store_true", help="Run only file removal and its policy controls")
    parser.add_argument("--rounds", type=int, default=1, help="Repetitions of each scenario")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    agent = args.agent.resolve(strict=True)
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="file-read-") as tmp:
        checks = ["FileReadCheck", "LinkedReadCheck", "DirectoryCheck", "DirectoryWalkCheck", "DeleteEntryCheck"]
        if args.delete_only:
            checks = ["DeleteEntryCheck"]
        programs = checks if args.delete_only else [*checks, "DirectoryPolicyCheck"]
        subprocess.run(["javac", "-d", tmp, COMMON / "HttpTransportCheck.java", *(src / (c + ".java") for c in programs)], check=True)
        for name in checks:
            for mode in ("block", "monitor"):
                log = Path(tmp) / f"{name}-{mode}.jsonl"
                directory_check = name in ("DirectoryCheck", "DirectoryWalkCheck")
                rounds = args.rounds
                delete_check = name == "DeleteEntryCheck"
                fixture = Path(tmp) / f"reports-{mode}"
                scope = [f"-Dohmyrasp.file.delete_root={fixture}/tenant-reports"] if delete_check else []
                run = subprocess.run(["java", "-Xverify:all", *scope, f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                      f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                                      "-cp", tmp, name, track, mode, str(rounds), *([str(fixture)] if delete_check else [])], capture_output=True, text=True, timeout=45)
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                rows = [json.loads(line) for line in log.read_text().splitlines()]
                events = [e for e in rows if e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection"]
                if name == "DeleteEntryCheck":
                    if (len(events) != 7 * rounds or any(e["algorithm"] != "deleteFile_userinput"
                            or e["details"].get("decision_basis") != "escaping_entry"
                            or (e["action"] == "block") != (mode == "block") for e in events)
                            or sum(e["details"].get("file_operation", e["hook"]) == "descriptor_relative_unlink" for e in events) != rounds):
                        raise SystemExit(f"unexpected host removal evidence in {mode}")
                    cases = [line.split(",")[1] for line in run.stdout.splitlines() if line.startswith("row,")]
                    if not cases or any(n != rounds for n in Counter(cases).values()):
                        raise SystemExit(f"incomplete removal checks in {mode}")
                    print(f"{mode}: {len(set(cases))} delete scenarios x {rounds} round(s)")
                    continue
                if directory_check:
                    walk = name == "DirectoryWalkCheck"
                    rule = "directory_userinput" if track == "main" else f"java{track}_directory_userinput"
                    basis = "selected_directory_walk" if walk else "selected_directory"
                    if len(events) != rounds * (1 if walk else 5) or any(
                        e["algorithm"] != rule or e["details"]["path"] != "/etc"
                        or e["details"].get("decision_basis") != basis
                        or (e["action"] == "block") != (mode == "block") for e in events
                    ):
                        raise SystemExit(f"unexpected {name} decisions in {mode}")
                    if walk and track == "main" and any(e["request"]["uri"] != "/origin" for e in events):
                        raise SystemExit("deferred listing attributed to the consumer request")
                    continue
                algorithm = "readFile_userinput" if track == "main" else f"java{track}_file_sensitive_read"
                paths = [e["details"]["path"] for e in events]
                template_count = int(name == "LinkedReadCheck" and track == "main")
                if (paths.count("/etc/hosts") != 4 * rounds or len(paths) != (4 + template_count) * rounds
                        or sum(p.endswith("/WEB-INF/weekly.txt") for p in paths) != template_count * rounds):
                    raise SystemExit(f"unexpected {name} destinations in {mode}")
                if any(e["algorithm"] != algorithm or (e["action"] == "block") != (mode == "block") for e in events):
                    raise SystemExit(f"unexpected {name} decisions in {mode}")
                if name == "LinkedReadCheck" and any(e["details"].get("decision_basis") != "resolved_request_file"
                                                     for e in events):
                    raise SystemExit("linked read missing target evidence")

        log = Path(tmp) / "unscoped.jsonl"
        subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                        "-Dohmyrasp.mode=block", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                        "-cp", tmp, "DeleteEntryCheck", track, "unscoped"], check=True, timeout=45,
                       stdout=subprocess.DEVNULL)
        if log.exists() and any(e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection"
                                for e in map(json.loads, log.read_text().splitlines())):
            raise SystemExit("unexpected finding without a deletion boundary")

        if track == "main":
            log = Path(tmp) / "delete-policy.jsonl"
            subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                            "-Dohmyrasp.mode=block", "-Dohmyrasp.force_block=true", "-Dohmyrasp.log.sync=true",
                            f"-Dohmyrasp.log={log}", "-cp", tmp, "DeleteEntryCheck", "policy"], check=True, timeout=45)
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("kind") == "detection"]
            if [(e["algorithm"], e["action"], e["details"]["decision_basis"]) for e in events] != [
                ("deleteFile_userinput", "log", "requested_path_only")
            ]:
                raise SystemExit("unexpected managed delete decisions")

            if args.delete_only:
                return
            log = Path(tmp) / "directory-policy.jsonl"
            subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                            "-Dohmyrasp.mode=block", "-Dohmyrasp.force_block=true", "-Dohmyrasp.log.sync=true",
                            f"-Dohmyrasp.log={log}", "-cp", tmp, "DirectoryPolicyCheck"], check=True, timeout=45)
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("kind") == "detection"]
            if [(e["algorithm"], e["action"]) for e in events] != [
                ("directory_unwanted", "log"), ("directory_userinput", "log"), ("directory_reflect", "block")
            ]:
                raise SystemExit("unexpected managed directory decisions")


if __name__ == "__main__":
    main()
