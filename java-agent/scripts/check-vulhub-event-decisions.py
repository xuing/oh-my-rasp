#!/usr/bin/env python3
"""Recheck retained block decisions offline. Requires built backport jars and a JDK 17+.

Scans all Vulhub event files under --logs-dir, including exploratory runs. Each
historical block is either tested or given a skip reason. Prints aggregates and
writes a report without original inputs. Exit 1 for mismatches (or changed
records with --compare-report), benign alerts, or unresolved records with --require-complete; 2 for invalid input. No vulnerable application or shell script runs.
"""
import argparse
import base64
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# Known fields holding the observed argument (possibly normalized by the detector).
# Summaries of entire requests, call stacks or argv are not equivalent arguments.
SOURCES = {
    "ArchiveEntry.write": ("archiveWrite", "entry", "../report.csv -> /srv/orders/report.csv"),
    "FileInputStream.open": ("beforeFileRead", "path", "/srv/orders/report.csv"),
    "RandomAccessFile.open": ("beforeFileRead", "path", "/srv/orders/report.csv"),
    "UnixChannelFactory.open": ("beforeFileRead", "path", "/srv/orders/report.csv"),
    "FileOutputStream.open": ("beforeFileWrite", "path", "/srv/orders/report.csv"),
    "MultipartUpload.filename": ("beforeFileUpload", "filename", "orders.csv"),
    "Runtime.exec(String)": ("beforeRuntimeExecString", "command", "whoami"),
    "ScriptEngine.eval": ("beforeScriptEval", "script", "quantity * price"),
    "XMLEntityManager.setupCurrentEntity": ("beforeXmlEntity", "entity", "section relative.dtd"),
    "URLClassLoader": ("onClassDefinitionSource", "codebase", "URLClassLoader file file:/srv/app/classes/"),
    "RMIClassLoader": ("beforeRmiCodebaseLoader", "codebase", "RMIClassLoader file file:/srv/app/classes/"),
    "DriverManager.getConnection": ("beforeJdbcConnection", "jdbc_url", "jdbc:h2:mem:orders"),
    "org.h2.jdbc.JdbcConnection.<init>": ("beforeH2JdbcConnection", "jdbc_url", "jdbc:h2:mem:orders"),
}
SERVLET_SOURCES = {
    "request_path_confusion": ("requestPath", "uri", "/reports/weekly"),
    "request_internal_identity": ("requestIdentity", "request", "nacos-server\0/reports/health"),
}


def source_for(hook, algorithm, track):
    if hook == "JndiLoginModule.lookup" and algorithm == f"java{track}_jaas_jndi_remote_provider":
        return ("jndiRoute", "lookup", "java:comp/env/directory")
    if hook in ("InitialContext.lookup", "InitialContext.lookupLink", "URLContext.lookup", "URLContext.lookupLink"):
        if algorithm == f"java{track}_jndi_remote_lookup":
            return ("jndiRoute", "lookup", "java:comp/env/jdbc/orders")
        return None
    if hook in ("ObjectInputStream.resolveClass", "ObjectInputStream.resolveProxyClass"):
        if algorithm == f"java{track}_deserialization_gadget_class":
            return ("streamTypeName", "class", "java.util.ArrayList")
        return None
    if hook == "HttpServlet.service":
        prefix = f"java{track}_"
        return SERVLET_SOURCES.get(algorithm[len(prefix):]) if algorithm.startswith(prefix) else None
    return SOURCES.get(hook)


def identity_arguments(value):
    """The writer used the trimmed, lowercase user-agent and the unmodified servlet URI."""
    try:
        units = len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        return None
    if value.count(" uri=") != 1 or units > 1200:
        return None
    match = re.fullmatch(r"user-agent=([^\x00-\x1f\x7f]+) uri=(/[^\s?#\x00-\x1f\x7f]*)", value)
    if not match or match[1].strip() != match[1] or match[1].endswith(("...", "…")):
        return None
    return match[1] + "\0" + match[2]


START = re.compile(r"ohmyrasp-java(8|11|17)-agent-start")


def file_read_limit(value, basis):
    """The original namespace and request cannot be recovered from the policy target alone."""
    path = PurePosixPath(value)
    if basis in ("attachment_file_open", "resolved_request_file", "request_selected_hosts"):
        return "source evidence required", "recorded policy target only; original input and binding unavailable"
    if (basis == "normalized_read_location" or not path.is_absolute() or ".." in path.parts
            or path.root == "//" or PureWindowsPath(value).drive or os.name != "posix"):
        return "filesystem evidence required", "original path resolution, working directory or filesystem unavailable"
    if basis:
        return "source evidence required", "unrecognized file-read basis; a pathname cannot verify this decision"
    if path == PurePosixPath("/etc/hosts"):
        return "source evidence required", "opened path retained; request input and attachment source unavailable"
    return None


def process_evidence_limit(hook, algorithm, track, message, details):
    if algorithm == f"java{track}_command_execution_exploit_primitive":
        if hook == "Spring.initMethod":
            return "source evidence required", "parsed definition, selected method and process receiver require live observation"
        if details.get("decision_basis") == "bean_initialization" or message == f"Spring bean initialization reached a Java {track} process sink":
            return "source evidence required", "initialization frames cannot establish the XML origin or selected lifecycle receiver"
    if hook not in {"Runtime.exec(String)", "Runtime.exec(String[])", "ProcessBuilder.start",
                    "ProcessBuilder.startPipeline", "ProcessImpl.start"}:
        return None
    vector = hook != "Runtime.exec(String)"
    basis = details.get("decision_basis")
    if basis is not None and not isinstance(basis, str):
        return "decision evidence required", "invalid process decision basis"
    # Older backports identified the argument-only primitive through its message.
    # A reason emitted by a detector cannot reconstruct the original live caller.
    primitive = algorithm == f"java{track}_command_execution_exploit_primitive"
    argument_only = basis == "command_arguments" or (
        basis is None and message == f"Suspicious command execution reached a Java {track} process sink")
    if algorithm == f"java{track}_command_execution_shell_meta" and (
            basis == "shell_arguments" or message == f"Suspicious shell metacharacter command reached a Java {track} shell command"):
        return "source evidence required", "legacy shell text does not establish request input at a program operator"
    if ((primitive and not argument_only) or basis in {"request_shell_syntax", "configuration_launcher", "scheduled_script"}
            or message == f"Scheduler script job reached a Java {track} shell script process sink"):
        reason = "original request or launch stack unavailable"
        if vector:
            reason += "; argument boundaries also unavailable"
        return "source evidence required", reason
    if vector:
        return "argument evidence required", "display text cannot establish argv boundaries or empty arguments"
    return None


def collect(logs):
    rows = []
    batches = defaultdict(list)
    issues = []
    corpus_hash = hashlib.sha256()
    files = sorted(logs.glob("vulhub-*/**/events.jsonl"))
    for path in files:
        source = path.relative_to(logs).as_posix()
        track = None
        file_hash = hashlib.sha256()
        with path.open("rb") as stream:
            for number, line in enumerate(stream, 1):
                file_hash.update(line)
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    event = None
                if not isinstance(event, dict):
                    issues.append({"file": source, "line": number, "reason": "invalid record"})
                    continue
                event_name = event.get("event")
                if isinstance(event_name, str) and event_name.endswith("-agent-start"):
                    match = START.fullmatch(event_name)
                    track = match[1] if match else None
                if event.get("action") != "block":
                    continue
                hook, algorithm = event.get("hook"), event.get("algorithm")
                row = {"file": source, "line": number, "track": track, "hook": hook, "algorithm": algorithm}
                rows.append(row)
                if not isinstance(hook, str) or not isinstance(algorithm, str):
                    row["status"] = "invalid event"
                    issues.append({"file": source, "line": number, "reason": "missing decision identity"})
                    continue
                algorithm_track = re.match(r"java(\d+)_", algorithm)
                if not track or (algorithm_track and algorithm_track[1] != track):
                    row["status"] = "unknown or inconsistent agent track"
                    continue
                if hook == "OpenWire.createThrowable" and algorithm == f"java{track}_deserialization_protocol_class":
                    row.update(status="source evidence required",
                               evidence_limit="recorded name alone cannot verify the original constructor and its declaring class hierarchy")
                    continue
                if hook == "AppConfigurationEntry.<init>" and algorithm == f"java{track}_jaas_jndi_remote_provider":
                    row.update(status="source evidence required",
                               evidence_limit="configuration declaration only; no login module routing operand recorded")
                    continue
                if hook in ("SparkRest.handleSubmit", "RMWebServices.submitApplication") and algorithm == f"java{track}_request_remote_job_submission":
                    row.update(status="authorization evidence required",
                               evidence_limit="submission details alone cannot reproduce the deployment role and servlet decision")
                    continue
                if (hook in ("com.auth0.jwt.JWTVerifier.verify", "FilterChain.doFilter")
                        and algorithm == f"java{track}_request_jwt_verification_failure"):
                    row.update(status="source evidence required",
                               evidence_limit="credential selection, verifier outcome and filter-chain handoff unavailable")
                    continue
                if hook == "URL.openConnection":
                    row["evidence_limit"] = "factory event only; actual HTTP transport and selected route unknown"
                if hook in {"FileSystem.list", "DirectoryStream.open", "SecureDirectoryStream.open"}:
                    details = event.get("details")
                    basis = details.get("decision_basis") if isinstance(details, dict) else None
                    if basis in ("selected_directory", "selected_directory_walk"):
                        row.update(status="source evidence required", historical_decision_basis=basis,
                                   evidence_limit="reported directory only; original input, walk and filesystem identity unavailable")
                        continue
                details = event.get("details")
                if isinstance(details, dict):
                    if isinstance(details.get("decision_basis"), str):
                        row["historical_decision_basis"] = details["decision_basis"]
                    if details.get("process_operation") == "ProcessImpl.start":
                        row["historical_operation"] = "ProcessImpl.start"
                    limit = process_evidence_limit(hook, algorithm, track, event.get("message"), details)
                    if limit is not None:
                        row["status"], row["evidence_limit"] = limit
                        continue
                if (hook in ("SQL.identifier", "MyBatis.BoundSql") and algorithm == f"java{track}_sql_identifier_injection"
                        and isinstance(details, dict) and set(details) == {"identifier"}
                        and isinstance(details["identifier"], str)
                        and re.fullmatch(r"source=\S+ parameter=\S+ reason=\S+ valueLength=\d+", details["identifier"])):
                    if hook == "SQL.identifier":
                        row["status"] = "argument evidence required"
                        row["evidence_limit"] = "identifier reason and length recorded; original argument unavailable"
                    else:
                        row["status"] = "source evidence required"
                        row["evidence_limit"] = "order metadata recorded; raw substitution, offsets and JDBC handoff unavailable"
                    continue
                if (hook == "JmxMBeanServer.invoke" and isinstance(details, dict) and set(details) == {"invoke"}
                        and algorithm in (f"java{track}_jmx_remote_config_source", f"java{track}_jmx_script_file_write")):
                    row["status"] = "argument evidence required"
                    row["evidence_limit"] = "combined display text cannot establish resolved MBean dispatch or the original argument types"
                    continue
                if (hook == "FileOutputStream.write" and algorithm == f"java{track}_file_generated_plot_script_command"
                        and isinstance(details, dict) and "path" in details and set(details) <= {"path", "decision_basis"}):
                    row["status"] = "source evidence required"
                    row["evidence_limit"] = ("stream-bound write recorded; original bytes unavailable"
                                             if details.get("decision_basis") == "plot_stream_write" else
                                             "target path only; original write bytes and their association with the stream are missing")
                    continue
                source_spec = source_for(hook, algorithm, track)
                if source_spec is None:
                    row["status"] = "no offline adapter"
                    continue
                method, field, _ = source_spec
                value = details.get(field) if isinstance(details, dict) else None
                if method == "beforeXmlEntity" and isinstance(details, dict) and "decision_basis" not in details:
                    row["evidence_limit"] = "entity source recorded; actual transport opening unknown"
                if not isinstance(value, str) or not value or "[redacted]" in value or value.endswith(("...", "…")):
                    row["status"] = "argument unavailable"
                    continue
                if method == "jndiRoute":
                    basis = row.get("historical_decision_basis")
                    if basis is None or basis == "lookup_name_only":
                        if hook == "JndiLoginModule.lookup":
                            row.update(status="source evidence required", evidence_limit="login module routing basis missing")
                            continue
                        method = "jndiName"
                        row["evidence_limit"] = "display name only; original Name components and JDK provider route unknown"
                    elif basis == ("provider_root_lookup" if hook.startswith("URLContext.") else "url_scheme_selection"):
                        row["evidence_limit"] = "recorded routing operand only; provider response and network activity unknown"
                        row["_expected_detail"] = ("lookup", value, "routing_operand_matched")
                        value = hook + "\0" + value
                    else:
                        row.update(status="source evidence required", evidence_limit="unrecognized naming route basis")
                        continue
                if method == "streamTypeName":
                    row["evidence_limit"] = ("name policy only; the resolved Class and hierarchy are unavailable"
                                             if row.get("historical_decision_basis") else
                                             "name policy only; the legacy label cannot distinguish descriptors and interfaces")
                if method == "requestIdentity":
                    arguments = identity_arguments(value)
                    if arguments is None:
                        row["status"] = "argument unavailable"
                        continue
                    row["evidence_limit"] = "normalized header and URI classifier only; caller identity and authorization unknown"
                    row["_expected_detail"] = ("request", value, "identity_fields_matched")
                    value = arguments
                if method == "requestPath":
                    # The old event stored both strings in one abbreviated field. Only the
                    # original operand is an input; the normalized string is an independent check.
                    parts = value.split(" -> ")
                    if len(parts) != 2 or not all(parts) or not parts[0].startswith("/") or "?" in parts[0]:
                        row["status"] = "argument unavailable"
                        continue
                    row["evidence_limit"] = "URI classifier and normalized result only; original servlet dispatch and authorization unknown"
                    row["_expected_detail"] = ("uri", value, "normalized_path_matched")
                    value = parts[0]
                if hook == "MultipartUpload.filename" and algorithm == "fileUpload_java_archive":
                    if details.get("multipart_source") == "active_request_lookup":
                        row["historical_multipart_source"] = "active_request_lookup"
                    policy_digest = details.get("archive_policy_sha256")
                    if isinstance(policy_digest, str) and re.fullmatch("[0-9a-f]{64}", policy_digest):
                        row["recorded_archive_policy_sha256"] = policy_digest
                    row["status"] = "authorization evidence required"
                    row["evidence_limit"] = "submitted name alone cannot establish the original route policy and authorization"
                    continue
                if method == "beforeFileRead":
                    limit = file_read_limit(value, row.get("historical_decision_basis"))
                    if limit is not None:
                        row["status"], row["evidence_limit"] = limit
                        continue
                    if hook != "FileInputStream.open":
                        row.update(status="argument evidence required",
                                   evidence_limit="file API open mode or native flags and directory descriptor unavailable")
                        continue
                if method == "archiveWrite":
                    if row.get("historical_decision_basis") == "archive_descriptor_open":
                        row["status"] = "filesystem evidence required"
                        row["evidence_limit"] = "resolved target recorded; original directory descriptor and relative operand unavailable"
                        continue
                    paths = value.split(" -> ")
                    if len(paths) != 2 or not all(paths) or any(p.endswith(("...", "…")) for p in paths):
                        row["status"] = "argument unavailable"
                        continue
                    row["evidence_limit"] = "recorded path pair only; extraction root and filesystem unknown"
                if hook in ("RMIClassLoader", "URLClassLoader"):
                    basis = "rmi_codebase_loader_selection" if hook == "RMIClassLoader" else "url_class_definition"
                    if row.get("historical_decision_basis") != basis:
                        row.update(status="source evidence required",
                                   evidence_limit="configuration or annotation cannot establish loader selection or a class definition")
                        continue
                    row["_expected_detail"] = ("codebase", value, "codebase_url_matched")
                    parts = value.split(" ", 2)
                    if len(parts) != 3 or parts[0] != hook or not parts[2]:
                        row["status"] = "argument unavailable"
                        continue
                if method == "beforeXmlEntity" and (not value.partition(" ")[0] or not value.partition(" ")[2]):
                    row["status"] = "argument unavailable"
                    continue
                batches[track].append((row, method, value))
        corpus_hash.update(source.encode() + b"\0" + file_hash.digest())
    if not files:
        issues.append({"reason": "no Vulhub event files"})
    return files, rows, batches, issues, corpus_hash.hexdigest()


def check_batch(java, tmp, root, track, cases, controls):
    jar = root / f"agent-java{track}/build/libs/ohmyrasp-agent-java{track}.jar"
    probes = {(row["hook"], method, source_for(row["hook"], row["algorithm"], track)[2]) for row, method, _ in cases}
    for hook, method, safe in sorted(probes):
        samples = [hook + "\0" + safe if method == "jndiRoute" else safe]
        if method == "requestIdentity":
            samples.append("report-client/1.0\0/admin/reports")
        for sample in samples:
            control = {"track": track, "hook": hook, "probe": method}
            controls.append(control)
            cases.append((control, method, sample))
    log = tmp / "decision.jsonl"
    cmd = [java, "-Dohmyrasp.log.sync=true", "-Dohmyrasp.control=none", "-Dohmyrasp.mode=block",
           f"-Dohmyrasp.java{track}.block=true", f"-Dohmyrasp.java{track}.log={log}",
           "-cp", os.pathsep.join(map(str, (tmp, jar))), "EvidenceProbe", track, str(log)]
    data = "".join(method + "\t" + base64.b64encode(value.encode()).decode() + "\n" for _, method, value in cases)
    result = subprocess.run(cmd, input=data, text=True, capture_output=True, timeout=90)
    if result.returncode or len(result.stdout.splitlines()) != len(cases):
        raise ValueError(f"Java {track} probe did not return one result per input (exit {result.returncode})")
    for (row, method, _), response in zip(cases, result.stdout.splitlines(), strict=True):
        blocked, encoded = response.split("\t")
        if method in ("streamTypeName", "jndiName"):
            if blocked not in ("listed", "unlisted") or encoded:
                raise ValueError("invalid name policy receipt")
            if "algorithm" in row:
                row["status"] = "name policy matched" if blocked == "listed" else "name policy mismatch"
            else:
                row["status"] = "matched" if blocked == "unlisted" else "mismatch"
            continue
        if blocked not in ("true", "false"):
            raise ValueError("Java probe returned an invalid block receipt")
        events = [json.loads(line) for line in base64.b64decode(encoded, validate=True).splitlines()]
        record_probe_result(row, blocked == "true", events)
    return hashlib.sha256(jar.read_bytes()).hexdigest()


def record_probe_result(row, blocked, events):
    findings = [e for e in events if e.get("kind") != "telemetry"]
    decisions = [(e.get("algorithm"), e.get("action")) for e in findings]
    hooks = [e.get("hook") for e in findings]
    if "algorithm" in row:
        ok = blocked and hooks == [row["hook"]] and decisions == [(row["algorithm"], "block")]
    else:
        ok = not blocked and not findings
    details = findings[0].get("details") if len(findings) == 1 else None
    if not isinstance(details, dict):
        details = {}
    for source, key in (("historical_decision_basis", "decision_basis"), ("historical_operation", "process_operation")):
        if source in row:
            match = hooks == [row["hook"]] and row[source] == details.get(key)
            row[key + "_matched"] = match
            ok = ok and match
    expected = row.pop("_expected_detail", None)
    if expected is not None:
        key, value, result_key = expected
        row[result_key] = hooks == [row["hook"]] and details.get(key) == value
        ok = ok and row[result_key]
    row["status"] = "matched" if ok else "mismatch"
    if not ok:
        row.update(blocked=blocked, observed=decisions, observed_hooks=hooks)


def changed_decisions(previous, current):
    if previous.get("corpus_sha256") != current["corpus_sha256"] or previous.get("issues"):
        raise ValueError("comparison requires a valid reference report over the same event files")
    def index(report):
        return {(row["file"], row["line"]): row for row in report["historical_blocks"]}
    before, after = index(previous), index(current)
    if before.keys() != after.keys():
        raise ValueError("comparison reports contain different historical records")
    def outcome(row):
        return row["status"], row.get("blocked"), row.get("observed")
    changes = []
    for key, row in after.items():
        prior = before[key]
        same_receipts = all(prior[k] == row[k] for k in ("observed_hooks", "decision_basis_matched", "process_operation_matched")
                            if k in prior and k in row)
        if same_receipts and outcome(prior) == outcome(row):
            continue
        tested = {"matched", "mismatch"}
        name_only = {"name policy matched", "name policy mismatch"}
        outcomes = {prior["status"], row["status"]}
        changes.append({"file": key[0], "line": key[1], "before": prior["status"], "after": row["status"],
                        "kind": "detector outcome" if outcomes <= tested or outcomes <= name_only else "evidence availability"})
    return changes


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--logs-dir", type=Path, default=ROOT / "logs")
    p.add_argument("--agent-root", type=Path, default=ROOT, help="Java agent Gradle project containing built jars")
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--compare-report", type=Path, help="Compare decisions to a prior report over identical logs")
    p.add_argument("--require-complete", action="store_true",
                   help="Fail if any historical block is unresolved or differs, including in comparison mode.")
    args = p.parse_args()
    if args.compare_report and args.compare_report.resolve() == args.report.resolve():
        p.error("write the candidate report to a different file from the reference report")
    files, rows, batches, issues, digest = collect(args.logs_dir)
    jdk = Path(os.environ["JAVA_HOME"]) / "bin" if os.environ.get("JAVA_HOME") else None
    controls, jars = [], {}
    with tempfile.TemporaryDirectory(prefix="rasp-decisions-") as scratch:
        tmp = Path(scratch)
        source = ROOT / "scripts/evidence/EvidenceProbe.java"
        subprocess.run([jdk / "javac" if jdk else "javac", "--release", "8", "-d", tmp, source], check=True)
        for track, cases in sorted(batches.items()):
            jars[track] = check_batch(jdk / "java" if jdk else "java", tmp, args.agent_root, track, cases, controls)
    counts = Counter(row["status"] for row in rows)
    java = jdk / "java" if jdk else "java"
    version = subprocess.run([java, "-version"], text=True, capture_output=True, check=True)
    report = dict(files=len(files), corpus_sha256=digest, historical_blocks=rows, jar_sha256=jars,
                  probe_jvm=(version.stderr or version.stdout).splitlines()[0], benign_controls=controls, issues=issues)
    replayed = counts["matched"] + counts["mismatch"]
    unresolved = len(rows) - replayed
    report["replay_summary"] = {"replayed": replayed, "matched": counts["matched"],
                                "different": counts["mismatch"], "unresolved": unresolved,
                                "name_policy_matched": counts["name policy matched"],
                                "name_policy_different": counts["name policy mismatch"]}
    different = bool(counts["mismatch"] or counts["name policy mismatch"])
    if args.compare_report:
        changes = changed_decisions(json.loads(args.compare_report.read_text()), report)
        report["changes_from_reference"] = changes
        different = bool(changes)
        print(f"{len(changes)} changed historical records relative to the reference report: "
              f"{dict(Counter(change['kind'] for change in changes))}")
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(files)} event files, {len(rows)} historical blocks: {dict(counts)}")
    print(f"{replayed} replayed, {unresolved} unresolved. A full historical comparison requires every block to match.")
    if counts["name policy matched"] or counts["name policy mismatch"]:
        print(f"Unresolved records with a name-only check: {counts['name policy matched']} agree, "
              f"{counts['name policy mismatch']} differ.")
    print(f"Benign controls: {dict(Counter(row['status'] for row in controls))}")
    if issues or not batches:
        return 2
    incomplete = args.require_complete and (unresolved != 0 or counts["mismatch"] != 0)
    return int(different or incomplete or any(row["status"] != "matched" for row in controls))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Offline decision check failed: {exc}", file=sys.stderr)
        sys.exit(2)
