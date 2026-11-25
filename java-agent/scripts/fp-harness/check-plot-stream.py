#!/usr/bin/env python3
"""Check plot-byte ownership and write receipts on a packaged backport agent."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    jar = parser.parse_args().agent.resolve(strict=True)
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="plot-stream-") as tmp:
        subprocess.run(["javac", "-d", tmp, src / "HttpTransportCheck.java", src / "PlotStreamCheck.java"], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            subprocess.run(["java", "-Xverify:all", f"-javaagent:{jar}", "-Dohmyrasp.standalone=true",
                            f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                            "-cp", tmp, "PlotStreamCheck", mode], check=True, timeout=45)
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("event") == "ohmyrasp-detection"]
            if len(events) != 2 or any(not e["algorithm"].endswith("_file_generated_plot_script_command")
                    or e["action"] != ("block" if mode == "block" else "log")
                    or e["details"].get("decision_basis") != "plot_stream_write"
                    or Path(e["details"]["path"]).name != "chart.plot" for e in events):
                raise SystemExit(f"unexpected plot decisions in {mode}")


if __name__ == "__main__":
    main()
