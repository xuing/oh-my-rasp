#!/usr/bin/env python3
"""Check JDBC identifier decisions and database receipts on a local, in-memory SQLite database."""
import argparse
import hashlib
from pathlib import Path
import tempfile
from urllib.request import urlopen
import sys

COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(COMMON))
from jdbc_report_probe import check_reports


FIXTURES = (
    ("org/xerial/sqlite-jdbc/3.47.1.0/sqlite-jdbc-3.47.1.0.jar",
     "4164d95347aeab42b754cabb7945b93e54f29ddb2eded967dbe979b4045cb685"),
    ("org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar",
     "d3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0"),
)


def dependency(directory, artifact, digest, download):
    """The pinned JAR in `directory`, fetched there first when `download` is set."""
    jar = directory / artifact.split("/")[-1]
    if download:
        with urlopen("https://repo.maven.apache.org/maven2/" + artifact, timeout=40) as response:
            jar.write_bytes(response.read(20 * 1024 * 1024))
    if not jar.is_file():
        raise SystemExit(f"{jar} is missing: stage it with --stage-dir (probes/run.py stage does)")
    if hashlib.sha256(jar.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"unexpected fixture dependency digest for {jar.name}")
    return jar.resolve()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path, nargs="?")
    parser.add_argument("--stage-dir", type=Path, help="download the pinned driver and logging JARs for the runtime matrix")
    parser.add_argument("--jar-dir", type=Path, help="use the JARs staged in this directory; without it they are downloaded")
    args = parser.parse_args()
    if args.stage_dir:
        if args.agent or args.jar_dir:
            parser.error("--stage-dir stages the dependencies as a separate operation")
        args.stage_dir.mkdir(parents=True, exist_ok=True)
        for artifact, digest in FIXTURES:
            dependency(args.stage_dir, artifact, digest, download=True)
        return
    if not args.agent:
        parser.error("provide an agent JAR or --stage-dir")
    agent = args.agent.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="report-columns-") as tmp:
        directory = args.jar_dir or Path(tmp)
        jars = tuple(dependency(directory, artifact, digest, download=args.jar_dir is None) for artifact, digest in FIXTURES)
        check_reports(agent, Path(__file__).with_name("SqliteIdentifierCheck.java"), jars, scenario_count=17, selected_count=8)


if __name__ == "__main__":
    main()
