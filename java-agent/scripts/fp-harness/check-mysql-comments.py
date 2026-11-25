#!/usr/bin/env python3
"""Check MySQL-family report comments using a supplied MariaDB JDBC classpath and private local socket."""
import argparse
import os
from pathlib import Path

from jdbc_report_probe import check_reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--socket", required=True, type=Path, help="Local MariaDB socket accepting the reports test account")
    parser.add_argument("--driver-classpath", required=True, help="Connector/J and its local socket support libraries")
    args = parser.parse_args()
    socket = args.socket.resolve(strict=True)
    if not socket.is_socket():
        parser.error("--socket must name a Unix socket")
    libraries = [Path(path).resolve(strict=True) for path in args.driver_classpath.split(os.pathsep)]
    check_reports(args.agent.resolve(strict=True), "MysqlCommentCheck", libraries, scenario_count=9,
                  selected_count=3, extra=(str(socket),))


if __name__ == "__main__":
    main()
