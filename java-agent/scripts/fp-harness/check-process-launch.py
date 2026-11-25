#!/usr/bin/env python3
"""Verify actual process launches, argument handling and pipeline receipts on the runtime matrix."""
import argparse
from collections import Counter
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("agent", type=Path)
    parser.add_argument("--rounds", type=int, default=1, help="Repetitions of each scenario")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    rounds = args.rounds
    agent = args.agent.resolve(strict=True)
    src = Path(__file__).parent
    with zipfile.ZipFile(agent) as jar:
        track = next((v for v in ("8", "11", "17") if
                      f"io/ohmyrasp/agent/java{v}/Java{v}RaspHooks.class" in jar.namelist()), "main")
    with tempfile.TemporaryDirectory(prefix="process-launch-") as tmp:
        if os.name == "nt":
            pwsh = shutil.which("pwsh")
            if pwsh is None:
                parser.error("the Windows process check needs PowerShell 7.5 or later")
            subprocess.run(["javac", "-d", tmp, src / "WindowsProcessCheck.java", src / "HttpTransportCheck.java"], check=True)
            for mode in ("block", "monitor"):
                log = Path(tmp) / f"windows-{mode}.jsonl"
                run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                      "-Dohmyrasp.control=none", f"-Dohmyrasp.mode={mode}", "-Dohmyrasp.log.sync=true",
                                      f"-Dohmyrasp.log={log}", "-cp", tmp, "WindowsProcessCheck", track, mode, pwsh, str(rounds)],
                                     capture_output=True, text=True, timeout=90)
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                events = [e for line in log.read_text().splitlines() if (e := json.loads(line)).get("algorithm")]
                rule = "command_userinput" if track == "main" else f"java{track}_command_execution_shell_meta"
                if len(events) != 2 * rounds or any(e["algorithm"] != rule or (e["action"] == "block") != (mode == "block")
                                           or e["details"].get("decision_basis") != "request_shell_syntax"
                                           or e["details"].get("process_operation") != "ProcessImpl.start" for e in events):
                    raise SystemExit(f"unexpected Windows launch decisions in {mode}: {events}")
            return
        version = subprocess.run(["javac", "-version"], text=True, capture_output=True, check=True)
        checks = ["ProcessLaunchCheck"]
        if "javac 1.8." not in version.stdout + version.stderr:
            checks.append("ProcessPipelineCheck")
        if track == "main":
            curl = shutil.which("curl")
            if curl is None:
                parser.error("the primary process-launch check needs curl for the loopback transfer")
            checks.extend(["GeneratedOutputCheck", "RenderedWriteCheck", "CallbackCommandCheck"])
        sources = [src / (n + ".java") for n in [*checks, "HttpTransportCheck", "ProcessPolicyCheck"]]
        subprocess.run(["javac", "-d", tmp, *sources], check=True)
        baseline = subprocess.run(["java", "-cp", tmp, "ProcessLaunchCheck", "list-baseline"],
                                  text=True, capture_output=True, timeout=20, check=True)
        reference_reads = int(baseline.stdout.strip())
        if track == "main":
            checks.append("ProcessPolicyCheck")
        for name in checks:
            managed = name == "ProcessPolicyCheck"
            for mode in (["block"] if managed else ["block", "monitor"]):
                log = Path(tmp) / f"{name}-{mode}.jsonl"
                rendered = name in ("GeneratedOutputCheck", "RenderedWriteCheck")
                probe_args = [mode, str(rounds)] if rendered else [track, mode, str(rounds)]
                if name == "CallbackCommandCheck":
                    probe_args = [mode, curl, str(rounds)]
                run = subprocess.run(["java", "-Xverify:all", f"-javaagent:{agent}", "-Dohmyrasp.standalone=true",
                                      f"-Dohmyrasp.force_block={str(managed).lower()}", f"-Dohmyrasp.mode={mode}",
                                      "-Dohmyrasp.log.sync=true", f"-Dohmyrasp.log={log}", "-cp", tmp,
                                      name, *probe_args], capture_output=True, text=True, timeout=60)
                if run.returncode:
                    raise SystemExit(run.stdout + run.stderr)
                if name == "ProcessLaunchCheck":
                    reads = [int(line.split(",")[1]) for line in run.stdout.splitlines() if line.startswith("reads,")]
                    if reads != [reference_reads] * rounds:
                        raise SystemExit("agent changed access to the application's command list")
                rows = [json.loads(line) for line in log.read_text().splitlines()]
                events = [e for e in rows if e.get("kind") == "detection" or e.get("event") == "ohmyrasp-detection"]
                if name == "CallbackCommandCheck":
                    if len(events) != 2 * rounds or any(
                            e["algorithm"] != "command_dnslog" or e["details"].get("host") != "probe.dnslog.cn"
                            or e["details"].get("process_operation") != "ProcessImpl.start"
                            or (e["action"] == "block") != (mode == "block") for e in events):
                        raise SystemExit(f"unexpected callback destination decisions in {mode}")
                    continue
                if name in ("GeneratedOutputCheck", "RenderedWriteCheck"):
                    if len(events) != 2 * rounds or any(e["algorithm"] != "writeFile_generated_script"
                                                or (e["action"] == "block") != (mode == "block") for e in events):
                        raise SystemExit("unexpected generated-output decisions")
                    continue
                if managed:
                    if Counter((e["algorithm"], e["action"]) for e in events) != {
                            ("command_reflect", "log"): rounds, ("command_reflect", "block"): rounds}:
                        raise SystemExit("unexpected reflection policy decisions")
                else:
                    api = Counter(e["details"].get("process_api", e["hook"]) for e in events)
                    expected = ({"ProcessBuilder.startPipeline": 2 * rounds} if name == "ProcessPipelineCheck" else
                                {"Runtime.exec(String)": rounds, "Runtime.exec(String[])": rounds, "ProcessBuilder.start": 3 * rounds})
                    if name == "ProcessLaunchCheck":
                        rule = "command_common" if track == "main" else f"java{track}_command_execution_exploit_primitive"
                        commands = [e["details"].get("command") for e in events if e["algorithm"] == rule]
                        if commands != ["/bin/sh -c cat '/etc/passwd'"] * rounds:
                            raise SystemExit(f"unexpected literal process decisions in {mode}")
                    if api != expected or any((e["action"] == "block") != (mode == "block") for e in events):
                        observed = Counter((e["algorithm"], e["details"].get("process_api", e["hook"]), e["action"]) for e in events)
                        raise SystemExit(f"unexpected {name} decisions in {mode}: {dict(observed)}")
                if any(e["details"].get("process_operation") != "ProcessImpl.start"
                       or int(e["details"]["argument_count"]) != 3 for e in events):
                    raise SystemExit("missing launch evidence")


if __name__ == "__main__":
    main()
