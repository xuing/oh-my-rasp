"""Compare read-only JDBC receipts with all detections emitted by a packaged agent."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile

import agent_track


def check_reports(agent, fixture, libraries, scenario_count, selected_count, extra=()):
    track = agent_track.track(agent) or "main"
    fixture_source, fixture = fixture, fixture.stem
    with tempfile.TemporaryDirectory(prefix="jdbc-receipts-") as tmp:
        work = Path(tmp)
        subprocess.run(["javac", "-cp", os.pathsep.join(map(str, libraries)), "-d", tmp,
                        Path(__file__).with_name("HttpTransportCheck.java"), fixture_source], check=True)
        for mode in ("block", "monitor"):
            log = work / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                            f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                            "-cp", os.pathsep.join(map(str, (work, *libraries))),
                            fixture, track, mode, *extra], capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            receipts = [line.split(",") for line in run.stdout.splitlines() if line.startswith("receipt,")]
            if (len(receipts) != scenario_count or len({r[1] for r in receipts}) != scenario_count
                    or sum(r[2] == "true" for r in receipts) != selected_count):
                raise SystemExit("incomplete SQL receipts")
            spool = log.read_bytes()
            previous = 0
            algorithm = "sql_policy" if track == "main" else f"java{track}_sql_statement_injection"
            action = "block" if mode == "block" else "log"
            for _, name, selected, _, _, encoded, start, end in receipts:
                start, end = int(start), int(end)
                if not previous <= start <= end <= len(spool) or detections(spool[previous:start]):
                    raise SystemExit(f"unexpected events outside {name} in {mode}")
                previous = end
                query = base64.b64decode(encoded, validate=True).decode()
                events = detections(spool[start:end])
                wrong_receipt = any(e["algorithm"] != algorithm or e["action"] != action
                                    or e["details"].get("query") != query for e in events)
                if bool(events) != (selected == "true") or wrong_receipt or (mode == "block" and len(events) > 1):
                    raise SystemExit(f"unexpected JDBC decisions for {name} in {mode}")
            if detections(spool[previous:]):
                raise SystemExit(f"unexpected events after final JDBC receipt in {mode}")


def detections(chunk):
    return [e for line in chunk.splitlines() if (e := json.loads(line)).get("kind", e.get("event"))
            in ("detection", "ohmyrasp-detection")]
