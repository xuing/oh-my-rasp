#!/usr/bin/env python3
"""Check a release transport decoder with locally generated valid compressed blocks."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--jar-dir", type=Path, required=True, help="Elasticsearch release runtime libraries")
    args = parser.parse_args()
    jar = args.agent.resolve(strict=True)
    source = Path(__file__).with_name("ElasticReleaseBlockCheck.java")
    with tempfile.TemporaryDirectory(prefix="elastic-lz4-") as work:
        cp = os.pathsep.join((work, str(args.jar_dir.resolve(strict=True) / "*")))
        subprocess.run(["javac", "-cp", cp, "-d", work, source], check=True)
        for mode in ("block", "monitor", "off"):
            subprocess.run(["java", "-Xverify:all", f"-javaagent:{jar}", "-Dohmyrasp.standalone=true",
                            "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log=none",
                            "-cp", cp, "ElasticReleaseBlockCheck", mode], check=True, timeout=60)


if __name__ == "__main__":
    main()
