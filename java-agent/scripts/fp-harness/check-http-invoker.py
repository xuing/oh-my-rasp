#!/usr/bin/env python3
"""Verify Spring RPC reads, nested type enforcement and explicit protocol policy."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--jar-dir", type=Path, required=True)
    parser.add_argument("--api-dir", type=Path, required=True)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    api, = args.api_dir.glob("javax.servlet-api-*.jar")
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="invoker-read-") as tmp:
        cp = os.pathsep.join((tmp, str(args.jar_dir / "*"), str(api)))
        subprocess.run(["javac", "-cp", cp, "-d", tmp, src / "HttpInvokerReadCheck.java",
                        src / "HttpTransportCheck.java", src / "stream-types/listed/BeanComparator.java"], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                  "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                  f"-Dohmyrasp.log={log}", "-cp", cp, "HttpInvokerReadCheck", track, mode],
                                 text=True, capture_output=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
            typed = "deserialization_gadget" if track == "main" else f"java{track}_deserialization_gadget_class"
            expected = [typed]
            if track == "main":
                expected += ["deserialization_http_invoker", "deserialization_http_object_stream"]
            if ([e["algorithm"] for e in events] != expected
                    or any((e["action"] == "block") != (mode == "block") for e in events)
                    or events[0]["details"].get("class") != "org.apache.commons.beanutils.BeanComparator"):
                raise SystemExit(f"unexpected {mode} decisions: {events}")
            if track == "main" and [e["details"].get("decision_basis") for e in events[1:]] != [
                    "invocation_stream_read", "servlet_stream_read"]:
                raise SystemExit("missing object-read evidence")


if __name__ == "__main__":
    main()
