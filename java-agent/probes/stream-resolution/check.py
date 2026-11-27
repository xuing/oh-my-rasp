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
import sys

COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(COMMON))
import agent_track  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path, nargs="?")
    parser.add_argument("--download-to", type=Path, help="stage the pinned fixture for the runtime matrix")
    parser.add_argument("--beanshell-jar", type=Path, help="use the pinned fixture library from disk")
    parser.add_argument("--collections-dir", type=Path, help="include actual Commons Collections 3 and 4 round trips")
    args = parser.parse_args()
    if args.download_to and (args.agent or args.beanshell_jar or args.collections_dir):
        parser.error("--download-to stages the dependency as a separate operation")
    if not args.download_to and not args.agent:
        parser.error("provide an agent JAR or --download-to")
    with tempfile.TemporaryDirectory(prefix="stream-resolution-") as tmp:
        library = args.download_to or args.beanshell_jar or Path(tmp) / "bsh.jar"
        if args.beanshell_jar is None:
            with urlopen("https://repo.maven.apache.org/maven2/org/apache-extras/beanshell/bsh/2.0b6/bsh-2.0b6.jar",
                         timeout=45) as response:
                data = response.read()
        else:
            data = library.read_bytes()
        if hashlib.sha256(data).hexdigest() != "a17955976070c0573235ee662f2794a78082758b61accffce8d3f8aedcd91047":
            raise SystemExit("unexpected BeanShell fixture library")
        if args.beanshell_jar is None:
            library.parent.mkdir(parents=True, exist_ok=True)
            library.write_bytes(data)
        if args.download_to:
            return
        agent = args.agent.resolve(strict=True)
        src = Path(__file__).parent
        track = agent_track.track(agent) or "main"
        classpath = [tmp, str(library)]
        if args.collections_dir:
            classpath.append(str(args.collections_dir / "*"))
        cp = os.pathsep.join(classpath)
        subprocess.run(["javac", "-cp", cp, "-d", tmp, COMMON / "HttpTransportCheck.java", src / "StreamResolutionCheck.java",
                        *sorted((COMMON / "stream-types").rglob("*.java"))], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                  "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                  f"-Dohmyrasp.log={log}", "-cp", cp, "StreamResolutionCheck", track, mode,
                                  *(["collections"] if args.collections_dir else [])],
                                 capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            events = [r for r in rows if r.get("kind") == "detection" or r.get("event") == "ohmyrasp-detection"]
            names = Counter(e["details"]["class"] for e in events)
            if names != {"org.apache.commons.beanutils.BeanComparator": 7 if args.collections_dir else 3,
                         "org.apache.xalan.xsltc.trax.TemplatesImpl": 1} or any(
                             (e["action"] == "block") != (mode == "block") for e in events):
                raise SystemExit(f"incorrect type decisions on {track} in {mode}")
            if track != "main":
                for event in events:
                    proxy = event["details"]["class"].endswith(".TemplatesImpl")
                    if (event["algorithm"] != f"java{track}_deserialization_gadget_class"
                            or event["hook"] != ("ObjectInputStream.resolveProxyClass" if proxy else "ObjectInputStream.resolveClass")
                            or event["details"]["decision_basis"] != ("resolved_proxy_interface" if proxy else "resolved_class")):
                        raise SystemExit("incorrect resolver evidence")


if __name__ == "__main__":
    main()
