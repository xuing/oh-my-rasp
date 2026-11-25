#!/usr/bin/env python3
"""Exercise the packaged agent against ordinary and policy-controlled MyBatis mappings."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import zipfile

MYBATIS_VERSION = "3.5.19"
MYBATIS_SHA256 = "93eea616ae355751bd5fbabb57f0732713fbe79f3196f33c51a0aeeb4255862a"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--mybatis-jar", type=Path, help="Use a local MyBatis distribution")
    args = parser.parse_args()
    jar = args.agent.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="mybatis-mapping-") as directory:
        work = Path(directory)
        if args.mybatis_jar:
            mybatis = args.mybatis_jar.resolve(strict=True)
        else:
            name = f"mybatis-{MYBATIS_VERSION}.jar"
            mybatis = work / name
            url = f"https://repo.maven.apache.org/maven2/org/mybatis/mybatis/{MYBATIS_VERSION}/{name}"
            with urllib.request.urlopen(url, timeout=45) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != MYBATIS_SHA256:
                raise SystemExit("MyBatis JAR digest mismatch")
            mybatis.write_bytes(data)
        source = Path(__file__).with_name("MyBatisMappingCheck.java")
        subprocess.run(["javac", "-cp", mybatis, "-d", work, source], check=True)
        with zipfile.ZipFile(jar) as agent:
            primary = "io/ohmyrasp/agent/hook/OhMyRaspHooks.class" in agent.namelist()
        for mode in (("block", "monitor", "managed") if primary else ("block", "monitor")):
            runtime_mode = "block" if mode == "managed" else mode
            log = work / (mode + ".jsonl")
            command = ["java", "-Xverify:all", "-Dohmyrasp.standalone=true", f"-Dohmyrasp.mode={runtime_mode}",
                       "-Dohmyrasp.control=none", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                       f"-javaagent:{jar}", "-cp", os.pathsep.join(map(str, (work, mybatis))), "MyBatisMappingCheck", mode]
            run = subprocess.run(command, capture_output=True, text=True, timeout=60)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            events = [json.loads(line) for line in log.read_text().splitlines()]
            decisions = [e for e in events if e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection"]
            if mode == "managed":
                algorithms = sorted(e.get("algorithm") for e in decisions)
                if algorithms != ["sql_identifier_injection"] * 2 + ["sql_policy"] * 2 or any(
                        e.get("action") != "log" for e in decisions):
                    raise SystemExit("independent mapper and generic SQL policies were not preserved")
                continue
            if len(decisions) != 2 or any((e.get("action") == "block") != (mode == "block") or
                    e.get("details", {}).get("decision_basis") != "mapper_substitution_at_jdbc" or
                    "query" in e.get("details", {}) for e in decisions):
                raise SystemExit("unexpected MyBatis evidence in " + mode)


if __name__ == "__main__":
    main()
