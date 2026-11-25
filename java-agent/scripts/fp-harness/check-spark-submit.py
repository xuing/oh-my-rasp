#!/usr/bin/env python3
"""Test Spark submission authorization using a recording servlet. No Spark service or job runs."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile

from servlet_fixture import APIS, api_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--api-dir", type=Path, help="use the pinned servlet API jars from disk")
    parser.add_argument("--spark-classpath", help="also verify the real Spark 2.3.1 servlet using distribution jars")
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    source = Path(__file__).with_name("spark")
    with zipfile.ZipFile(agent) as jar:
        prefix = next((f"java{v}_" for v in ("8", "11", "17") if
                       f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "")
    with tempfile.TemporaryDirectory(prefix="spark-submit-") as tmp:
        for namespace in APIS:
            classes = Path(tmp) / namespace
            classes.mkdir()
            api = api_jar(namespace, classes, args.api_dir)
            sources = []
            for src in sorted(source.glob("*.java")):
                dest = classes / src.name
                dest.write_text(src.read_text().replace("import javax.servlet", f"import {namespace}.servlet"))
                sources.append(dest)
            subprocess.run(["javac", "-cp", api, "-d", classes, *sources], check=True)
            verify(agent, prefix, classes, os.pathsep.join(map(str, (classes, api))), "SparkSubmitCheck", 2)
        if args.spark_classpath:
            classes = Path(tmp) / "release"
            classes.mkdir()
            cp = os.pathsep.join((str(classes), str(api_jar("javax", classes, args.api_dir)), args.spark_classpath))
            subprocess.run(["javac", "-cp", cp, "-d", classes, source.parent / "SparkReleaseServletCheck.java"], check=True)
            verify(agent, prefix, classes, cp, "SparkReleaseServletCheck", 1, ["-Dohmyrasp.spark.submitRole=submitter"])


def verify(agent, prefix, classes, cp, probe, expected, options=()):
    for mode in ("monitor", "block"):
        log = classes / f"{mode}.jsonl"
        run = subprocess.run(["java", "-Xverify:all", *options, f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                              "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", f"-Dohmyrasp.log={log}",
                              "-Dohmyrasp.log.sync=true", "-cp", cp,
                              probe, mode], capture_output=True, text=True, timeout=45)
        if run.returncode:
            raise SystemExit(run.stdout + run.stderr)
        rows = [json.loads(line) for line in log.read_text().splitlines()]
        events = [r for r in rows if r.get("kind") == "detection" or r.get("event") == "ohmyrasp-detection"]
        if len(events) != expected or any(r["algorithm"] != prefix + "request_remote_job_submission"
                or r["details"].get("decision_basis") != "required_submit_role_denied"
                or (r["action"] == "block") != (mode == "block") or "weekly.jar" in json.dumps(r) for r in events):
            raise SystemExit(f"incorrect Spark role receipts in {classes.name} / {mode}")


if __name__ == "__main__":
    main()
