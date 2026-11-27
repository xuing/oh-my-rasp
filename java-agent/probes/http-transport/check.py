#!/usr/bin/env python3
"""Verify HTTP transport decisions of a packaged agent on a loopback-only fixture."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

COMMON = Path(__file__).resolve().parent.parent / "common"
sys.path.insert(0, str(COMMON))
import agent_track  # noqa: E402


def check_address_lookups(agent, sources, directory):
    name = "HttpAddressLookupCheck"
    classes = directory / "resolver"
    services = classes / "META-INF" / "services"
    services.mkdir(parents=True)
    (services / "java.net.spi.InetAddressResolverProvider").write_text(name + "\n")
    subprocess.run(["javac", "-cp", agent, "-d", classes, sources / (name + ".java")], check=True)
    classpath = os.pathsep.join(map(str, (classes, agent)))
    subprocess.run(["java", "-cp", classpath, name], check=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    args = parser.parse_args()
    agent = args.agent.resolve(strict=True)
    sources = Path(__file__).parent
    track = agent_track.track(agent) or "main"
    with tempfile.TemporaryDirectory(prefix="http-transport-") as tmp:
        directory = Path(tmp)
        javac = subprocess.run(["javac", "-version"], text=True, capture_output=True, check=True)
        if track == "main":
            check_address_lookups(agent, sources, directory)
        classes = {"HttpTransportCheck": COMMON}
        if "javac 1.8." not in javac.stdout + javac.stderr:
            classes["HttpExchangeCheck"] = sources
        subprocess.run(["javac", "-d", directory, *(folder / (c + ".java") for c, folder in classes.items())], check=True)
        for name in classes:
            for mode in ("block", "monitor"):
                log = directory / f"{name}-{mode}.jsonl"
                command = ["java", "-Xverify:all", "-Dohmyrasp.standalone=true", f"-Dohmyrasp.mode={mode}",
                           "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}", f"-javaagent:{agent}",
                           "-cp", directory, name, track, mode]
                run = subprocess.run(command, text=True, capture_output=True, timeout=45)
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                events = [json.loads(l) for l in log.read_text().splitlines()]
                decisions = [e for e in events if e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection"]
                expected = 4 if name == "HttpTransportCheck" else 1
                if len(decisions) != expected or any((e["action"] == "block") != (mode == "block") for e in decisions):
                    raise SystemExit(f"unexpected {name} decision count or action in {mode}")
                if name == "HttpTransportCheck":
                    metadata = "ssrf_aws" if track == "main" else f"java{track}_ssrf_cloud_metadata"
                    if sum(e["algorithm"] == metadata for e in decisions) != 1:
                        raise SystemExit(f"incorrect metadata address classification in {mode}")
                    target = "http://[fe80::a%25FloorA]/weekly-fixture"
                    if sum(e["details"].get("url") == target for e in decisions) != 1:
                        raise SystemExit(f"scoped destination missing from {mode} evidence")
                if any(e["details"].get("decision_basis") not in {
                        "http_transport_acquire", "http_exchange_acquire", "http_request_write"
                } for e in decisions) or "fixture-private-ticket" in json.dumps(decisions):
                    raise SystemExit(f"incorrect transport evidence from {name}")


if __name__ == "__main__":
    main()
