#!/usr/bin/env python3
"""Verify RPC reads, nested type enforcement and explicit protocol policies."""
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
    parser.add_argument("--jar-dir", type=Path, required=True)
    parser.add_argument("--api-dir", type=Path, required=True)
    parser.add_argument("--xmlrpc-dir", type=Path, help="also exercise the Apache XML-RPC extension reader")
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    api, = args.api_dir.glob("javax.servlet-api-*.jar")
    src = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="invoker-read-") as tmp:
        libraries = [tmp, str(args.jar_dir / "*"), str(api)]
        checks = ["HttpInvokerReadCheck"]
        if args.xmlrpc_dir:
            checks.append("XmlRpcReadCheck")
            libraries.append(str(args.xmlrpc_dir / "*"))
        cp = os.pathsep.join(libraries)
        subprocess.run(["javac", "-cp", cp, "-d", tmp, *(src / (name + ".java") for name in checks),
                        COMMON / "HttpTransportCheck.java", COMMON / "stream-types/listed/BeanComparator.java"], check=True)
        for check in checks:
            for mode in ("block", "monitor"):
                log = Path(tmp) / f"{check}-{mode}.jsonl"
                run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                      "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                      f"-Dohmyrasp.log={log}", "-cp", cp, check, track, mode],
                                     text=True, capture_output=True, timeout=45)
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
                typed = "deserialization_gadget" if track == "main" else f"java{track}_deserialization_gadget_class"
                if track == "main" and check == "XmlRpcReadCheck":
                    local = events.pop() if events else {}
                    details = local.get("details", {})
                    if (local.get("action") != ("log" if mode == "block" else "monitor")
                            or local.get("algorithm") != typed or "stream_operation" in details
                            or details.get("class") != "org.apache.commons.beanutils.BeanComparator"):
                        raise SystemExit(f"unblocked local stream reported an incorrect decision: {local}")
                typed_count = 2 if check == "XmlRpcReadCheck" else 1
                expected = [typed] * typed_count
                bases = []
                if track == "main":
                    if check == "XmlRpcReadCheck":
                        expected.append("deserialization_xmlrpc_serialized")
                        bases = ["xmlrpc_extension_read"]
                    else:
                        expected += ["deserialization_http_invoker", "deserialization_http_object_stream"]
                        bases = ["invocation_stream_read", "servlet_stream_read"]
                if ([e["algorithm"] for e in events] != expected
                        or any((e["action"] == "block") != (mode == "block") for e in events)
                        or any(e["details"].get("class") != "org.apache.commons.beanutils.BeanComparator" for e in events[:typed_count])):
                    raise SystemExit(f"unexpected {mode} decisions: {events}")
                if [e["details"].get("decision_basis") for e in events[typed_count:]] != bases:
                    raise SystemExit(f"missing {check} object-read evidence")
                if check == "XmlRpcReadCheck" and track == "main" and any(
                        e["details"].get("stream_operation") != "xmlrpc_extension_read" for e in events[:typed_count]):
                    raise SystemExit("XML-RPC filter did not retain its stream")


if __name__ == "__main__":
    main()
