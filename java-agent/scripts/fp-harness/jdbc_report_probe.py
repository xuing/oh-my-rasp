"""Compare read-only JDBC receipts with all detections emitted by a packaged agent."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def check_reports(agent, fixture, libraries, scenario_count, selected_count, extra=()):
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    source = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="jdbc-receipts-") as tmp:
        work = Path(tmp)
        subprocess.run(["javac", "-cp", os.pathsep.join(map(str, libraries)), "-d", tmp, source / "HttpTransportCheck.java",
                        source / (fixture + ".java")], check=True)
        for mode in ("block", "monitor"):
            log = work / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                            f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                            "-cp", os.pathsep.join(map(str, (work, *libraries))),
                            fixture, track, mode, *extra], capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            receipts = [line.split(",") for line in run.stdout.splitlines() if line.startswith("receipt,")]
            expected_queries = {base64.b64decode(r[5], validate=True).decode() for r in receipts if r[2] == "true"}
            if len(receipts) != scenario_count or len({r[1] for r in receipts}) != scenario_count or len(expected_queries) != selected_count:
                raise SystemExit("incomplete SQL receipts")
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("kind", e.get("event"))
                      in ("detection", "ohmyrasp-detection")]
            expected = "sql_policy" if track == "main" else f"java{track}_sql_statement_injection"
            if {e["details"].get("query") for e in events} != expected_queries or any(e["algorithm"] != expected or e["action"] != ("block" if mode == "block" else "log")
                                 for e in events):
                raise SystemExit(f"unexpected JDBC decisions in {mode}")
