#!/usr/bin/env python3
"""Check that the agent's own event writes do not trigger its file-write rule, with a .jsp spool in a web root."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

COMMON = Path(__file__).resolve().parent.parent / "common"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    jar = parser.parse_args().agent.resolve(strict=True)
    with zipfile.ZipFile(jar) as archive:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in archive.namelist()), "main")
    source = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="own-writes-") as tmp:
        work = Path(tmp)
        subprocess.run(["javac", "-d", tmp, COMMON / "HttpTransportCheck.java", source / "OwnWritesCheck.java"], check=True)
        for sync in ("true", "false"):
            root = work / sync / "webapps" / "ROOT"
            root.mkdir(parents=True)
            spool, target = root / "events.jsp", root / "upload.jsp"
            try:
                run = subprocess.run(["java", f"-javaagent:{jar}", "-Dohmyrasp.standalone=true", "-Dohmyrasp.mode=block",
                                      f"-Dohmyrasp.log.sync={sync}", f"-Dohmyrasp.log={spool}",
                                      "-cp", tmp, "OwnWritesCheck", track, str(target)],
                                     text=True, capture_output=True, timeout=60)
            except subprocess.TimeoutExpired:
                raise SystemExit(f"log.sync={sync}: the JVM did not finish")
            if run.returncode or "done" not in run.stdout.splitlines():
                raise SystemExit(f"log.sync={sync}: exit {run.returncode}\n{run.stdout[-2000:]}{run.stderr[-3000:]}")
            if "row,denied,true,created,false" not in run.stdout.splitlines():
                raise SystemExit(f"log.sync={sync}: the application's script write was not blocked\n{run.stdout}")
            if "StackOverflowError" in run.stderr or "event writer error" in run.stderr:
                raise SystemExit(f"log.sync={sync}: the agent re-entered its own write\n{run.stderr[-3000:]}")
            events = [json.loads(line) for line in spool.read_text(encoding="utf-8").splitlines()] if spool.exists() else []
            detections = [e for e in events if e.get("kind", e.get("event")) in ("detection", "ohmyrasp-detection")]
            paths = [str(e.get("details", {}).get("path", "")) for e in detections]
            if len(detections) != 1 or not paths[0].endswith("upload.jsp") or detections[0].get("action") != "block":
                raise SystemExit(f"log.sync={sync}: expected one block of upload.jsp, got {paths} "
                                 f"{[e.get('action') for e in detections]}")


if __name__ == "__main__":
    main()
