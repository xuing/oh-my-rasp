#!/usr/bin/env python3
"""Check JDBC identifier decisions and database receipts on a local, in-memory SQLite database."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from urllib.request import urlopen
import zipfile


def dependency(directory, local, artifact, digest):
    if local:
        jar = local.resolve(strict=True)
    else:
        jar = directory / artifact.split("/")[-1]
        with urlopen("https://repo.maven.apache.org/maven2/" + artifact, timeout=40) as response:
            jar.write_bytes(response.read(20 * 1024 * 1024))
    if hashlib.sha256(jar.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"unexpected fixture dependency digest for {jar.name}")
    return jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--driver", type=Path)
    parser.add_argument("--slf4j-api", type=Path)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    source = Path(__file__).parent
    with tempfile.TemporaryDirectory(prefix="report-columns-") as tmp:
        work = Path(tmp)
        sqlite = dependency(work, args.driver, "org/xerial/sqlite-jdbc/3.47.1.0/sqlite-jdbc-3.47.1.0.jar",
                            "4164d95347aeab42b754cabb7945b93e54f29ddb2eded967dbe979b4045cb685")
        logging = dependency(work, args.slf4j_api, "org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar",
                             "d3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0")
        subprocess.run(["javac", "-cp", str(sqlite), "-d", tmp, source / "HttpTransportCheck.java",
                        source / "SqliteIdentifierCheck.java"], check=True)
        for mode in ("block", "monitor"):
            log = work / f"{mode}.jsonl"
            run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                            f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}",
                            "-cp", os.pathsep.join(map(str, (work, sqlite, logging))),
                            "SqliteIdentifierCheck", track, mode], capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            receipts = [line.split(",") for line in run.stdout.splitlines() if line.startswith("receipt,")]
            expected_queries = {base64.b64decode(r[5], validate=True).decode() for r in receipts if r[2] == "true"}
            if len(receipts) != 6 or len(expected_queries) != 3:
                raise SystemExit("incomplete SQL receipts")
            events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("kind", e.get("event"))
                      in ("detection", "ohmyrasp-detection")]
            expected = "sql_policy" if track == "main" else f"java{track}_sql_statement_injection"
            if {e["details"].get("query") for e in events} != expected_queries or any(e["algorithm"] != expected or e["action"] != ("block" if mode == "block" else "log")
                                 for e in events):
                raise SystemExit(f"unexpected SQLite decisions in {mode}")


if __name__ == "__main__":
    main()
