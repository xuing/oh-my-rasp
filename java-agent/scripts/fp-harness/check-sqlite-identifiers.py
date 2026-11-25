#!/usr/bin/env python3
"""Check JDBC identifier decisions and database receipts on a local, in-memory SQLite database."""
import argparse
import hashlib
from pathlib import Path
import tempfile
from urllib.request import urlopen

from jdbc_report_probe import check_reports


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
    with tempfile.TemporaryDirectory(prefix="report-columns-") as tmp:
        work = Path(tmp)
        sqlite = dependency(work, args.driver, "org/xerial/sqlite-jdbc/3.47.1.0/sqlite-jdbc-3.47.1.0.jar",
                            "4164d95347aeab42b754cabb7945b93e54f29ddb2eded967dbe979b4045cb685")
        logging = dependency(work, args.slf4j_api, "org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar",
                             "d3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0")
        check_reports(agent, "SqliteIdentifierCheck", (sqlite, logging), scenario_count=6, selected_count=3)


if __name__ == "__main__":
    main()
