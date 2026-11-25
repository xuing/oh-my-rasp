#!/usr/bin/env python3
"""Check resolved JMX dispatch and preservation of application arguments in the packaged agent."""
import argparse
import json
import os
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
    algorithm = "jmx_remote_config" if track == "main" else f"java{track}_jmx_remote_config_source"
    write = "jmx_file_write" if track == "main" else f"java{track}_jmx_script_file_write"
    source = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="jmx-dispatch-") as work:
        subprocess.run(["javac", "-cp", str(jar), "-d", work, COMMON / "HttpTransportCheck.java",
                        source / "JmxDispatchCheck.java", source / "JmxAttributeLayoutCheck.java"], check=True)
        subprocess.run(["java", "-cp", os.pathsep.join((work, str(jar))), "JmxAttributeLayoutCheck", track], check=True)
        for mode in ("block", "monitor"):
            log = Path(work) / f"{mode}.jsonl"
            subprocess.run(["java", "-Xverify:all", f"-javaagent:{jar}", "-Dohmyrasp.standalone=true",
                            f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                            "-cp", work, "JmxDispatchCheck", track, mode], check=True, timeout=45)
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("kind") == "detection"
                      or e.get("event") == "ohmyrasp-detection"]
            action = "block" if mode == "block" else "log"
            if ([(e["algorithm"], e["action"]) for e in events] != [(write, action), (algorithm, action)]
                    or events[0]["details"].get("decision_basis") != "selected_write_open"):
                raise SystemExit(f"unexpected JMX decisions in {mode}")


if __name__ == "__main__":
    main()
