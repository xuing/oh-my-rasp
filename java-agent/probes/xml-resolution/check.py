#!/usr/bin/env python3
"""Check the packaged agent on the current JDK using real XML parsing and an in-memory transport."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jar", type=Path)
    parser.add_argument("--xerces-classpath", help="Optional Apache Xerces and XML APIs JAR classpath")
    args = parser.parse_args()
    jar = args.jar.resolve(strict=True)
    source = Path(__file__).with_name("XmlResolutionCheck.java")
    with tempfile.TemporaryDirectory(prefix="rasp-xml-check-") as work:
        tmp = Path(work)
        subprocess.run(["javac", "-d", work, source], check=True)
        application = tmp / "reports.jar"
        with zipfile.ZipFile(application, "w") as fixture:
            for compiled in tmp.glob("*.class"):
                fixture.write(compiled, compiled.name)
            fixture.writestr("catalog/stock.dtd", "<!ELEMENT order EMPTY><!ATTLIST order unit CDATA 'boxes'>")
        cp = str(application)
        provider = []
        if args.xerces_classpath:
            cp += os.pathsep + args.xerces_classpath
            provider = ["-Djavax.xml.parsers.DocumentBuilderFactory=org.apache.xerces.jaxp.DocumentBuilderFactoryImpl"]
        for mode in ("block", "monitor"):
            log = tmp / (mode + ".jsonl")
            log.touch()
            cmd = ["java", "-Dfixture.systemCatalog=true", "-Dohmyrasp.standalone=true", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.control=none",
                   "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}", f"-javaagent:{jar}",
                   *provider, "-cp", cp, "XmlResolutionCheck"]
            if mode == "monitor":
                cmd.append("observe")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if result.returncode:
                raise SystemExit(result.stdout + result.stderr)
            events = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
            if not any(e.get("event", "").endswith("-agent-start") for e in events) and (
                "[OHMYRASP] agent started with ASM transformer" not in result.stdout + result.stderr
            ):
                raise SystemExit("agent startup record missing")
            decisions = [e for e in events if e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection"]
            if mode == "block":
                if decisions:
                    raise SystemExit(f"{len(decisions)} detections on ordinary XML inputs")
            else:
                if len(decisions) != 3:
                    raise SystemExit(f"expected three transport decisions, observed {len(decisions)}")
                for e, destination in zip(decisions, ("!/catalog/order.dtd", "!/catalog/order.dtd", "http://catalog.example.invalid/forms/order.dtd")):
                    details = e["details"]
                    identifier = details.get("systemId", details.get("entity", ""))
                    if not (e["algorithm"] in {"xxe_protocol", "java8_xxe_external_entity_protocol",
                                               "java11_xxe_external_entity_protocol", "java17_xxe_external_entity_protocol"}
                            and identifier.endswith(destination) and details.get("decision_basis") == "parser_url_open"
                            and "catalogTicket" not in str(details) and e["action"] != "block"):
                        raise SystemExit("unexpected XML resolution decision")


if __name__ == "__main__":
    main()
