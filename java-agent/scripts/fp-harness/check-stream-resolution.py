#!/usr/bin/env python3
"""Check real ObjectInputStream resolver outcomes using inert report records and a BeanShell scalar."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.request import urlopen
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--beanshell-jar", type=Path, help="use the pinned fixture library from disk")
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    src = Path(__file__).parent
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    with tempfile.TemporaryDirectory(prefix="stream-resolution-") as tmp:
        library = args.beanshell_jar or Path(tmp) / "bsh.jar"
        if args.beanshell_jar is None:
            with urlopen("https://repo.maven.apache.org/maven2/org/apache-extras/beanshell/bsh/2.0b6/bsh-2.0b6.jar",
                         timeout=45) as response:
                library.write_bytes(response.read())
        if hashlib.sha256(library.read_bytes()).hexdigest() != "a17955976070c0573235ee662f2794a78082758b61accffce8d3f8aedcd91047":
            raise SystemExit("unexpected BeanShell fixture library")
        cp = os.pathsep.join((tmp, str(library)))
        subprocess.run(["javac", "-cp", cp, "-d", tmp, src / "HttpTransportCheck.java", src / "StreamResolutionCheck.java",
                        *sorted((src / "stream-types").rglob("*.java"))], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                  "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                  f"-Dohmyrasp.log={log}", "-cp", cp, "StreamResolutionCheck", track, mode],
                                 capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            events = [r for r in rows if r.get("kind") == "detection" or r.get("event") == "ohmyrasp-detection"]
            names = Counter(e["details"]["class"] for e in events)
            if names != {"org.apache.commons.beanutils.BeanComparator": 3,
                         "org.apache.commons.collections.functors.ConstantTransformer": 1} or any(
                             (e["action"] == "block") != (mode == "block") for e in events):
                raise SystemExit(f"incorrect type decisions on {track} in {mode}")
            if track != "main":
                for event in events:
                    proxy = event["details"]["class"].endswith(".ConstantTransformer")
                    if (event["algorithm"] != f"java{track}_deserialization_gadget_class"
                            or event["hook"] != ("ObjectInputStream.resolveProxyClass" if proxy else "ObjectInputStream.resolveClass")
                            or event["details"]["decision_basis"] != ("resolved_proxy_interface" if proxy else "resolved_class")):
                        raise SystemExit("incorrect resolver evidence")


if __name__ == "__main__":
    main()
