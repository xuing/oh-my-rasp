#!/usr/bin/env python3
"""Check the auth filter's decision at downstream dispatch with a deny-only receiver."""
import argparse
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
from servlet_fixture import api_jar

ARTIFACTS = (
    # java-jwt API used by the audited DataEase filter.
    ("com/auth0", "java-jwt", "3.12.1", "da3b695c3be2cdbf1c9e963e0db0d4509896696b640d77d6ec702a38f8cc4a70"),
    ("commons-codec", "commons-codec", "1.14", "a128e4f93fabe5381ded64cf2873019e06030b718eb43ceeae0b0e5d17ad33e9"),
    ("com/fasterxml/jackson/core", "jackson-annotations", "2.14.2", "2c6869d505cf60dc066734b7d50339f975bd3adc635e26a78abb71acb4473c0d"),
    ("com/fasterxml/jackson/core", "jackson-core", "2.14.2", "b5d37a77c88277b97e3593c8740925216c06df8e4172bbde058528df04ad3e7a"),
    ("com/fasterxml/jackson/core", "jackson-databind", "2.14.2", "501d3abce4d18dcc381058ec593c5b94477906bba6efbac14dae40a642f77424"),
)


def fixture_jars(directory, download):
    paths = []
    for group, name, version, digest in ARTIFACTS:
        filename = f"{name}-{version}.jar"
        path = directory / filename
        if download:
            url = f"https://repo.maven.apache.org/maven2/{group}/{name}/{version}/{filename}"
            with urlopen(url, timeout=45) as response:
                data = response.read()
        else:
            data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise SystemExit(f"dependency digest mismatch for {filename}")
        if download:
            path.write_bytes(data)
        paths.append(str(path))
    return paths


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path, nargs="?")
    parser.add_argument("--stage-dir", type=Path, help="download the fixture libraries for the runtime matrix")
    parser.add_argument("--jar-dir", type=Path, help="use local fixture dependencies")
    parser.add_argument("--api-dir", type=Path, help="use a separately staged Jakarta servlet API jar")
    args = parser.parse_args()
    if args.stage_dir:
        if args.agent or args.jar_dir or args.api_dir:
            parser.error("--stage-dir is a separate operation")
        args.stage_dir.mkdir(parents=True, exist_ok=True)
        fixture_jars(args.stage_dir, download=True)
        return
    if not args.agent:
        parser.error("provide an agent JAR or --stage-dir")
    agent = args.agent.resolve(strict=True)
    track = agent_track.track(agent) or "main"
    with tempfile.TemporaryDirectory(prefix="jwt-filter-") as tmp:
        work = Path(tmp)
        paths = [tmp, str(api_jar("jakarta", work, args.api_dir or args.jar_dir))]
        paths.extend(fixture_jars(args.jar_dir or work, download=args.jar_dir is None))
        cp = os.pathsep.join(paths)
        src = Path(__file__).parent
        subprocess.run(["javac", "-cp", cp, "-d", tmp, src / "JwtVerificationCheck.java",
                        *sorted((src / "dataease").glob("*.java"))], check=True)
        for mode in ("block", "monitor"):
            log = work / f"{mode}.jsonl"
            command = ["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                       "-Dohmyrasp.control=none", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                       f"-Dohmyrasp.mode={mode}", "-cp", cp, "JwtVerificationCheck", mode, track]
            run = subprocess.run(command, capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            rows = [json.loads(line) for line in log.read_text().splitlines()]
            events = [r for r in rows if r.get("kind") == "detection" or r.get("event") == "ohmyrasp-detection"]
            rule = ("" if track == "main" else f"java{track}_") + "request_jwt_verification_failure"
            if len(events) != 2 or any(e["algorithm"] != rule or (e["action"] == "block") != (mode == "block")
                                       or e["details"].get("decision_basis") != "rejected_token_dispatch"
                                       or "eyJ" in json.dumps(e) for e in events):
                raise SystemExit(f"incorrect JWT dispatch evidence in {mode} mode")


if __name__ == "__main__":
    main()
