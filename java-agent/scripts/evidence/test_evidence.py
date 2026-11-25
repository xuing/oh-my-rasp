import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
from vulhub_evidence import build_report

spec = importlib.util.spec_from_file_location("check_decisions", SCRIPTS / "check-vulhub-event-decisions.py")
decisions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decisions)


class EvidenceTest(unittest.TestCase):
    def test_catalog_relations_and_logs_are_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "logs"
            run = logs / "vulhub-example-protected"
            run.mkdir(parents=True)
            (root / "environments.toml").write_text(
                '[[environment]]\npath="app/one"\ncve=["CVE-2000-0001"]\n'
                '[[environment]]\npath="app/two"\ncve=["CVE-2000-0001"]\n')
            scripts = root / "scripts"
            scripts.mkdir()
            name = "acceptance-vulhub-example.sh"
            (scripts / name).write_text('# path app/one\nprotected_dir="logs/vulhub-example-protected"\n')
            (run / "events.jsonl").write_text(
                '{"hook":"example","algorithm":"test","action":"block","details":{"path":"PRIVATE-VALUE"}}\n'
                '{"hook":"http","algorithm":"latency","action":"observe","kind":"telemetry"}\ninvalid\n')
            inventory = build_report(root, {"app"}, [(7, f"CVE-2000-0001 `scripts/{name}`")], scripts, logs)
            a, b = inventory["environments"]
            self.assertEqual(a["exact_path_script_references"], [name])
            self.assertEqual(b["exact_path_script_references"], [])
            self.assertEqual(a["ledger_rows_sharing_identifier"], b["ledger_rows_sharing_identifier"])
            summary, = inventory["historical_logs"].values()
            self.assertEqual(summary["invalid_records"], 1)
            self.assertEqual(len(summary["decisions"]), 1)
            self.assertNotIn("PRIVATE-VALUE", json.dumps(inventory))

    def test_service_header_requires_two_unambiguous_recorded_fields(self):
        self.assertEqual(decisions.identity_arguments("user-agent=report client uri=/reports/health"),
                         "report client\0/reports/health")
        for raw in ("user-agent=client uri=/one uri=/two", "user-agent=report... uri=/ok",
                    "user-agent=one\0two uri=/ok", "user-agent=report uri=/path?private",
                    "user-agent=report uri=relative", "user-agent=report uri=/" + "📊" * 600):
            self.assertIsNone(decisions.identity_arguments(raw))
        self.assertIsNone(decisions.source_for("HttpServlet.service", "request_internal_identity", "8"))
        self.assertIsNone(decisions.source_for("HttpServlet.service", "java11_request_internal_identity", "8"))

    def test_spark_descriptor_does_not_establish_submit_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / "vulhub-fixture-protected"
            case.mkdir()
            records = [{"event": "ohmyrasp-java8-agent-start"}]
            for details in ({"submission": "Spark REST http jar descriptorHash=f00"},
                            {"operation": "handleSubmit", "decision_basis": "required_submit_role_denied"}):
                records.append({"hook": "SparkRest.handleSubmit", "action": "block",
                                "algorithm": "java8_request_remote_job_submission", "details": details})
            (case / "events.jsonl").write_text("\n".join(map(json.dumps, records)))
            _, rows, batches, issues, _ = decisions.collect(root)
            self.assertFalse(batches)
            self.assertFalse(issues)
            self.assertTrue(all(r["status"] == "authorization evidence required" for r in rows))

    def test_verifier_diagnostic_cannot_establish_filter_continuation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / "vulhub-fixture-protected"
            case.mkdir()
            records = [{"event": "ohmyrasp-java17-agent-start"}]
            for hook in ("com.auth0.jwt.JWTVerifier.verify", "FilterChain.doFilter"):
                records.append({"action": "block", "algorithm": "java17_request_jwt_verification_failure",
                                "hook": hook, "details": {"exception": "SignatureVerificationException"}})
            (case / "events.jsonl").write_text("\n".join(map(json.dumps, records)))
            _, rows, batches, _, _ = decisions.collect(root)
            self.assertEqual([r["status"] for r in rows], ["source evidence required"] * 2)
            self.assertFalse(batches)

    def test_sql_identifier_summary_does_not_stand_in_for_original_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / "vulhub-fixture-protected"
            case.mkdir()
            summary = "source=ReportDAO parameter=title reason=sql-comment valueLength=19"
            def event(hook, detail):
                return {"action": "block", "algorithm": "java8_sql_identifier_injection",
                        "hook": hook, "details": detail}
            records = [{"event": "ohmyrasp-java8-agent-start"}, event("SQL.identifier", {"identifier": summary}),
                       event("MyBatis.BoundSql", {"identifier": summary}),
                       event("SQL.identifier", {"identifier": summary, "other": "additional data"})]
            (case / "events.jsonl").write_text("\n".join(map(json.dumps, records)))
            _, rows, batches, _, _ = decisions.collect(root)
            self.assertEqual([row["status"] for row in rows],
                             ["argument evidence required", "source evidence required", "no offline adapter"])
            self.assertFalse(batches)

    def test_archive_descriptor_cannot_be_recreated_from_its_resolved_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / "vulhub-fixture-protected"
            case.mkdir()
            member = "/reports/weekly.txt"
            details = {"entry": member + " -> " + member, "decision_basis": "archive_descriptor_open"}
            event = {"action": "block", "algorithm": "java8_archive_entry_traversal_write",
                     "hook": "ArchiveEntry.write", "details": details}
            (case / "events.jsonl").write_text("\n".join(map(json.dumps, [
                {"event": "ohmyrasp-java8-agent-start"}, event])))
            _, rows, batches, _, _ = decisions.collect(root)
            self.assertEqual(rows[0]["status"], "filesystem evidence required")
            self.assertFalse(batches)

    def test_missing_context_and_multi_argument_commands_are_not_invented(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / "vulhub-fixture-protected"
            case.mkdir()
            rows = [
                {"action":"block", "algorithm":"java8_file_sensitive_read", "hook":"FileInputStream.open"},
                {"event":"ohmyrasp-java8-agent-start"},
                {"action":"block", "algorithm":"java8_file_sensitive_read", "hook":"FileInputStream.open",
                 "details":{"path":"[redacted]"}},
                {"action":"block", "algorithm":"java8_command_execution_shell_meta", "hook":"ProcessBuilder.start",
                 "details":{"command":"two arguments"}},
            ]
            (case / "events.jsonl").write_text("\n".join(map(json.dumps, rows)))
            _, records, batches, issues, _ = decisions.collect(root)
            self.assertEqual([r["status"] for r in records],
                             ["unknown or inconsistent agent track", "argument unavailable", "argument evidence required"])
            self.assertFalse(batches)
            self.assertFalse(issues)


    def test_historical_read_inputs_do_not_resolve_against_the_probe_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local = root / "visible"
            local.mkdir()
            (local / "report").touch()
            (root / "elsewhere").symlink_to(local, target_is_directory=True)
            case = root / "vulhub-fixture-protected"
            case.mkdir()
            source = case / "events.jsonl"
            def record(path, basis=None, hook="FileInputStream.open"):
                details = {"path": path}
                if basis:
                    details["decision_basis"] = basis
                return {"action": "block", "algorithm": "java8_file_sensitive_read", "hook": hook, "details": details}
            inputs = [record(str(root / "elsewhere" / ".." / "visible" / "report")),
                      record("report"), record("/etc/./hosts"),
                      record("/etc/passwd", "resolved_request_file", "UnixChannelFactory.open"),
                      record("/etc/issue", "normalized_read_location"), record("/etc/issue"),
                      record("/etc", "selected_directory_walk", "DirectoryStream.open")]
            source.write_text("\n".join(map(json.dumps, [{"event": "ohmyrasp-java8-agent-start"}, *inputs])))
            for _ in range(2):
                _, rows, batches, issues, _ = decisions.collect(root)
                self.assertEqual([row.get("status") for row in rows],
                                 ["filesystem evidence required", "filesystem evidence required",
                                  "source evidence required", "source evidence required",
                                  "filesystem evidence required", None, "source evidence required"])
                self.assertEqual([value for _, _, value in batches["8"]], ["/etc/issue"])
                self.assertFalse(issues)
                (root / "elsewhere").unlink(missing_ok=True)

    def test_process_source_and_argument_boundaries_are_independent(self):
        rule = "java8_command_execution_exploit_primitive"
        plain = "Suspicious command execution reached a Java 8 process sink"
        self.assertIsNone(decisions.process_evidence_limit("Runtime.exec(String)", rule, "8", plain, {}))
        for hook in ("ProcessBuilder.start", "Runtime.exec(String[])", "ProcessBuilder.startPipeline"):
            self.assertEqual(decisions.process_evidence_limit(hook, rule, "8", plain, {})[0],
                             "argument evidence required")
            status, reason = decisions.process_evidence_limit(hook, rule, "8", "", {"decision_basis":"database_stack"})
            self.assertEqual(status, "source evidence required")
            self.assertIn("argument boundaries", reason)
        self.assertEqual(decisions.process_evidence_limit("Runtime.exec(String)", rule, "8",
                         "Dynamic expression evaluation reached a Java 8 process sink", {})[0],
                         "source evidence required")

    def test_archive_authorization_is_not_inferred_from_a_name_or_an_emitted_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / "vulhub-fixture-protected"
            case.mkdir()
            rows = [{"event":"ohmyrasp-java8-agent-start"}]
            for basis in (None, "required_role_denied", "archive_upload_denied"):
                details = {"filename":"weekly.jar"}
                if basis:
                    details["decision_basis"] = basis
                rows.append({"action":"block", "hook":"MultipartUpload.filename",
                             "algorithm":"fileUpload_java_archive", "details":details})
            (case / "events.jsonl").write_text("\n".join(map(json.dumps, rows)))
            _, records, batches, issues, _ = decisions.collect(root)
            self.assertFalse(issues)
            self.assertFalse(batches)
            self.assertEqual([r["status"] for r in records], ["authorization evidence required"] * 3)
            self.assertEqual(records[-1]["historical_decision_basis"], "archive_upload_denied")

    def test_replay_requires_the_recorded_hook_and_any_recorded_basis(self):
        source = {"hook": "FileInputStream.open", "algorithm": "file", "historical_decision_basis": "path"}
        finding = {"hook": source["hook"], "algorithm": "file", "action": "block",
                   "details": {"decision_basis": "path"}}
        for observed, expected in ((finding, "matched"), (dict(finding, hook="other"), "mismatch"),
                                   (dict(finding, details={}), "mismatch"),
                                   (dict(finding, details={"decision_basis": "other"}), "mismatch")):
            row = dict(source)
            decisions.record_probe_result(row, True, [{"kind": "telemetry"}, observed])
            self.assertEqual(row["status"], expected)
            self.assertEqual(row["decision_basis_matched"], expected == "matched")
        row = dict(source, historical_operation="ProcessImpl.start")
        decisions.record_probe_result(row, True, [finding])
        self.assertFalse(row["process_operation_matched"])
        self.assertEqual(row["status"], "mismatch")
        row = dict(source)
        decisions.record_probe_result(row, True, [finding, finding])
        self.assertEqual(row["status"], "mismatch")

    def test_stream_type_policy_is_separate_from_a_replayed_decision(self):
        for hook in ("ObjectInputStream.resolveClass", "ObjectInputStream.resolveProxyClass"):
            spec = decisions.source_for(hook, "java17_deserialization_gadget_class", "17")
            self.assertEqual(spec[0], "streamTypeName")
            self.assertIsNone(decisions.source_for(hook, "java17_other_rule", "17"))
        def report(status):
            return {"corpus_sha256": "a", "issues": [], "historical_blocks": [
                {"file": "a", "line": 1, "status": status}]}
        change, = decisions.changed_decisions(report("matched"), report("name policy matched"))
        self.assertEqual(change["kind"], "evidence availability")
        change, = decisions.changed_decisions(report("name policy matched"), report("name policy mismatch"))
        self.assertEqual(change["kind"], "detector outcome")

    def test_compare_preserves_visible_mismatches_and_checks_input_identity(self):
        record = {"file": "a", "line": 2, "status": "mismatch", "observed": []}
        before = {"corpus_sha256": "a", "historical_blocks": [record], "issues": []}
        self.assertEqual(decisions.changed_decisions(before, before), [])
        annotated = dict(before, historical_blocks=[dict(record, evidence_limit="transport unknown")])
        self.assertEqual(decisions.changed_decisions(before, annotated), [])
        changed_verdict = dict(before, historical_blocks=[dict(record, observed=[["example", "log"]])])
        change, = decisions.changed_decisions(before, changed_verdict)
        self.assertEqual(change["kind"], "detector outcome")
        unavailable = dict(before, historical_blocks=[dict(record, status="source evidence required")])
        change, = decisions.changed_decisions(before, unavailable)
        self.assertEqual(change["kind"], "evidence availability")
        changed = dict(before, historical_blocks=[dict(record, status="matched")])
        self.assertEqual(len(decisions.changed_decisions(before, changed)), 1)
        with self.assertRaises(ValueError):
            decisions.changed_decisions(before, dict(before, corpus_sha256="b"))
