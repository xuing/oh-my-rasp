#!/usr/bin/env python3
"""Verify the type contract at the constructor call and preserve the vendor's own rejections."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--jar-dir", required=True, type=Path)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    versions = set()
    for pattern in ("activemq-client-*.jar", "activemq-openwire-legacy-*.jar"):
        lib, = args.jar_dir.glob(pattern)
        with zipfile.ZipFile(lib) as jar:
            found = {int(m[1]) for entry in jar.namelist() if
                     (m := re.fullmatch(r"org/apache/activemq/openwire/v([0-9]+)/BaseDataStreamMarshaller\.class", entry))}
            if not found:
                raise SystemExit(f"no marshallers in {lib}")
            versions.update(found)
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="openwire-types-") as tmp:
        cp = os.pathsep.join((tmp, str(args.jar_dir / "*")))
        subprocess.run(["javac", "-cp", cp, "-d", tmp, src / "OpenWireThrowableCheck.java",
                        *sorted((src / "openwire").rglob("*.java"))], check=True)
        for mode in ("block", "monitor", "off"):
            log = Path(tmp) / f"{mode}.jsonl"
            p = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.control=none", "-Dohmyrasp.log.sync=true",
                                f"-Dohmyrasp.log={log}", "-cp", cp, "OpenWireThrowableCheck", mode,
                                ",".join(map(str, sorted(versions)))], text=True, capture_output=True, timeout=40)
            if p.returncode:
                raise SystemExit(p.stdout + p.stderr)
            lines = [] if mode == "off" and not log.exists() else log.read_text().splitlines()
            events = [e for line in lines if (e := json.loads(line)).get("algorithm")]
            rule = "deserialization_protocol_class" if track == "main" else f"java{track}_deserialization_protocol_class"
            if len(events) != (0 if mode == "off" else 1) or any(
                    e["algorithm"] != rule or (e["action"] == "block") != (mode == "block")
                    or e["details"].get("class") != "org.apache.activemq.openwire.v42.BaseDataStreamMarshaller$ReportValue"
                    or e["details"].get("decision_basis") != "non_throwable_constructor"
                    or "private report text" in str(e) for e in events):
                raise SystemExit(f"unexpected OpenWire decisions in {mode}: {events}")


if __name__ == "__main__":
    main()
