#!/usr/bin/env python3
"""Check the JDK naming router with in-process default and URL providers."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    agent = parser.parse_args().agent.resolve(strict=True)
    src = Path(__file__).parent
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    version = subprocess.run(["javac", "-version"], capture_output=True, text=True, check=True)
    exports = [] if "javac 1.8" in version.stdout + version.stderr else [
        "--add-exports", "java.naming/com.sun.jndi.toolkit.url=ALL-UNNAMED"]
    with tempfile.TemporaryDirectory(prefix="jndi-route-") as tmp:
        subprocess.run(["javac", *exports, "-d", tmp, src / "HttpTransportCheck.java",
                        src / "JndiRouteCheck.java", src / "JaasDirectoryCheck.java", src / "jndi/ldapURLContextFactory.java"], check=True)
        for mode in ("block", "monitor"):
            log = Path(tmp) / f"{mode}.jsonl"
            run = subprocess.run(["java", *exports, "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                  "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                  f"-Dohmyrasp.log={log}", "-cp", tmp, "JndiRouteCheck", track, mode],
                                 capture_output=True, text=True, timeout=45)
            if run.returncode:
                raise SystemExit(run.stdout + run.stderr)
            events = [r for l in log.read_text().splitlines() if (r := json.loads(l)).get("kind") == "detection"
                      or r.get("event") == "ohmyrasp-detection"]
            rule = "jndi_disable_all" if track == "main" else f"java{track}_jndi_remote_lookup"
            login_rule = "jndi_jaas_config" if track == "main" else f"java{track}_jaas_jndi_remote_provider"
            observed = Counter((e["algorithm"], e["details"].get("operation", e["hook"]),
                                e["details"].get("decision_basis")) for e in events)
            if any(e["details"].get("requestControlled") == "true" for e in events):
                raise SystemExit("shared report name was treated as control over the directory URL")
            expected = {(rule, "InitialContext.lookup", "url_scheme_selection"): 3,
                        (rule, "InitialContext.lookupLink", "url_scheme_selection"): 1,
                        (rule, "URLContext.lookup", "provider_root_lookup"): 1,
                        (login_rule, "JndiLoginModule.lookup", "url_scheme_selection"): 1}
            if track == "main" and mode == "block":
                expected[(rule, "InitialContext.lookup", "url_scheme_selection")] += 1
            if observed != expected or any((e["action"] == "block") != (mode == "block") for e in events):
                raise SystemExit(f"unexpected JNDI decisions in {mode}: {dict(observed)}")


if __name__ == "__main__":
    main()
