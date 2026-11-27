//! Tests against the agent-daemon contract fixtures, `java-agent/contracts/agent-daemon/`.
//!
//! The Java agent and this daemon share two files and no code. The fixtures are the one place
//! the format is written down as examples; the Java tests read the same files. See the
//! README beside them for the normalisation rules and for how to regenerate.
//!
//! * `control/*.json` are produced here, by the real [`Controller`], and compared byte for byte.
//! * `events/**` are produced by the agent's writers; every line goes through the daemon's real
//!   parsing path ([`AgentEvent::parse_line`]) and the body it would upload.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::control::{ControlState, Controller, Mode, OutsideRequest};
use crate::model::{AgentEvent, CloudIdentity, DiagnosticFormat, EventClass};
use crate::store::EventStore;

/// What `updated_at` is replaced with in a golden control document.
const FIXED_UPDATED_AT: &str = "2026-01-01T00:00:00Z";

/// A cloud policy as the control plane serves it: JSON text the daemon passes through verbatim.
const POLICY: &str = r#"{"version":4,"status":"active","canary_percent":100,"rules":[{"algorithm":"sql_userinput","action":"block"}]}"#;

/// A cloud policy whose `config` carries the control plane's `protection.hardening` setting with
/// `outside_request` set to log, as `GetAgentPolicy` serves it.
const POLICY_OUTSIDE_LOG: &str = r#"{"version":6,"status":"active","rules":[],"config":{"hardening":{"mode":"monitor","outside_request":"log"}}}"#;

/// A policy whose text needs every kind of JSON string escape once it is carried as a string
/// member of the control file: quotes, backslash, newline, tab, a control character, and non-ASCII
/// text including a character outside the basic plane.
const ESCAPED_POLICY: &str = "{\"version\":5,\"status\":\"active\",\"rules\":[{\"algorithm\":\"sql_userinput\",\"action\":\"log\",\"note\":\"a \\\"quote\\\", back\\\\slash,\\nnew line,\\ttab,\\u0001 control, caf\u{e9} \u{1F600}\"}]}";

fn contracts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../java-agent/contracts/agent-daemon")
}

fn updating() -> bool {
    std::env::var("OHMYRASP_CONTRACTS_UPDATE").is_ok_and(|v| v == "1")
}

/// The control file at `path` with its one volatile field fixed. The writer puts one member per
/// line, so the field is found line by line.
fn normalized_control(path: &Path) -> String {
    let text = fs::read_to_string(path).expect("control file written");
    let mut out = Vec::new();
    let mut found = 0;
    for line in text.lines() {
        match line.trim_start().strip_prefix("\"updated_at\": \"") {
            Some(rest) => {
                let value = rest.trim_end_matches(',').trim_end_matches('"');
                assert!(is_rfc3339_utc(value), "updated_at is RFC 3339 UTC: {value}");
                let comma = if line.ends_with(',') { "," } else { "" };
                out.push(format!("  \"updated_at\": \"{FIXED_UPDATED_AT}\"{comma}"));
                found += 1;
            }
            None => out.push(line.to_string()),
        }
    }
    assert_eq!(found, 1, "exactly one updated_at in {text}");
    out.join("\n")
}

/// `2026-06-06T12:00:00Z` or the same with a fractional second.
fn is_rfc3339_utc(value: &str) -> bool {
    let b = value.as_bytes();
    value.ends_with('Z')
        && b.len() >= 20
        && [4, 7].iter().all(|&i| b[i] == b'-')
        && b[10] == b'T'
        && [13, 16].iter().all(|&i| b[i] == b':')
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
}

/// Drives the real controller through the desired states and returns each document it wrote,
/// with the state the controller held when it wrote it.
fn control_documents() -> Vec<(&'static str, String, ControlState)> {
    let dir = tempfile::tempdir().unwrap();
    let mut docs = Vec::new();

    // The mode, from the first document the daemon writes on a fresh install.
    let path = dir.path().join("modes.json");
    let ctrl = Controller::load_or_init(&path, Mode::Block).unwrap();
    docs.push(("mode-block", normalized_control(&path), ctrl.snapshot()));
    ctrl.update(Some(Mode::Monitor), None).unwrap();
    docs.push(("mode-monitor", normalized_control(&path), ctrl.snapshot()));
    ctrl.update(Some(Mode::Off), None).unwrap();
    docs.push(("mode-off", normalized_control(&path), ctrl.snapshot()));

    // A switch turned off and one turned back on, then a cloud policy, then its withdrawal.
    let path = dir.path().join("policy.json");
    let ctrl = Controller::load_or_init(&path, Mode::Block).unwrap();
    let switches = [
        ("sql_userinput".to_string(), false),
        ("xss_userinput".to_string(), true),
    ];
    ctrl.update(None, Some(switches.into_iter().collect()))
        .unwrap();
    docs.push((
        "algorithms-switched",
        normalized_control(&path),
        ctrl.snapshot(),
    ));
    assert!(ctrl.set_policy(Some(POLICY.to_string())).unwrap());
    docs.push((
        "policy-installed",
        normalized_control(&path),
        ctrl.snapshot(),
    ));
    assert!(ctrl.set_policy(None).unwrap());
    docs.push((
        "policy-withdrawn",
        normalized_control(&path),
        ctrl.snapshot(),
    ));

    // A policy that needs every JSON string escape.
    let path = dir.path().join("escaped.json");
    let ctrl = Controller::load_or_init(&path, Mode::Block).unwrap();
    assert!(ctrl.set_policy(Some(ESCAPED_POLICY.to_string())).unwrap());
    docs.push(("policy-escaped", normalized_control(&path), ctrl.snapshot()));

    // Findings outside a request logged instead of blocked: set on the console, then by the cloud.
    let path = dir.path().join("outside.json");
    let ctrl = Controller::load_or_init(&path, Mode::Block).unwrap();
    ctrl.update_with(None, Some(OutsideRequest::Log), None)
        .unwrap();
    docs.push((
        "outside-request-log",
        normalized_control(&path),
        ctrl.snapshot(),
    ));
    let path = dir.path().join("outside-policy.json");
    let ctrl = Controller::load_or_init(&path, Mode::Block).unwrap();
    assert!(
        ctrl.set_policy(Some(POLICY_OUTSIDE_LOG.to_string()))
            .unwrap()
    );
    docs.push((
        "outside-request-from-policy",
        normalized_control(&path),
        ctrl.snapshot(),
    ));
    docs
}

fn assert_golden(relative: &str, actual: &str) {
    let file = contracts().join(relative);
    if updating() {
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, format!("{actual}\n")).unwrap();
        return;
    }
    let golden = fs::read_to_string(&file).unwrap_or_else(|e| panic!("{relative}: {e}"));
    assert_eq!(
        golden.trim_end_matches('\n'),
        actual,
        "{relative} no longer matches what the daemon writes. If the format change is intended, \
         regenerate with OHMYRASP_CONTRACTS_UPDATE=1 cargo test (see \
         java-agent/contracts/agent-daemon/README.md), review the diff, and run the agent tests too."
    );
}

/// `control/expected.properties`: what each document means, read by the Java tests too.
fn expected() -> std::collections::BTreeMap<String, String> {
    let text = fs::read_to_string(contracts().join("control/expected.properties")).unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once('=')
                .unwrap_or_else(|| panic!("not key=value: {l}"));
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect()
}

/// Asserts the manifest entry of `document` describes `state`.
fn assert_manifest(document: &str, state: &ControlState) {
    let expected = expected();
    let get = |field: &str| -> String {
        expected
            .get(&format!("{document}.{field}"))
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(get("mode"), state.mode.as_str(), "{document} mode");
    assert_eq!(
        get("outside_request"),
        state.outside_request.as_str(),
        "{document} outside_request"
    );
    assert_eq!(
        get("revision"),
        state.revision.to_string(),
        "{document} revision"
    );
    let names = |want: bool| {
        state
            .algorithms
            .iter()
            .filter(|(_, enabled)| **enabled == want)
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    let listed = |field: &str| {
        get(field)
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(",")
    };
    assert_eq!(
        listed("disabled"),
        names(false),
        "{document} disabled switches"
    );
    assert_eq!(
        listed("enabled"),
        names(true),
        "{document} enabled switches"
    );
    match &state.policy {
        None => assert_eq!(get("policy"), "none", "{document} policy"),
        Some(text) => {
            assert_eq!(get("policy"), "control-file", "{document} policy");
            let version = serde_json::from_str::<Value>(text).unwrap()["version"].to_string();
            assert_eq!(get("policy.version"), version, "{document} policy version");
        }
    }
}

#[test]
fn the_controller_writes_the_golden_control_documents() {
    for (name, text, state) in control_documents() {
        assert_golden(&format!("control/{name}.json"), &text);
        assert_manifest(name, &state);
    }
}

#[test]
fn the_manifest_and_the_golden_control_documents_list_the_same_documents() {
    let documents: BTreeSet<String> = control_documents()
        .into_iter()
        .map(|(n, _, _)| n.to_string())
        .collect();
    let on_disk: BTreeSet<String> = json_names(&contracts().join("control"));
    let in_manifest: BTreeSet<String> = expected()
        .keys()
        .filter_map(|k| k.strip_suffix(".mode").map(str::to_string))
        .collect();
    assert_eq!(on_disk, documents, "control/*.json against the scenarios");
    assert_eq!(
        in_manifest, documents,
        "expected.properties against the scenarios"
    );
}

/// A restart: the daemon reads back what it wrote, keeps its state and rewrites the same bytes.
#[test]
fn the_daemon_reloads_its_own_golden_documents_unchanged() {
    for (name, _, state) in control_documents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let golden = fs::read_to_string(contracts().join(format!("control/{name}.json"))).unwrap();
        fs::write(&path, &golden).unwrap();

        let ctrl = Controller::load_or_init(&path, Mode::Off).unwrap();

        let reloaded = ctrl.snapshot();
        assert_eq!(reloaded.mode, state.mode, "{name} mode");
        assert_eq!(
            reloaded.outside_request, state.outside_request,
            "{name} outside_request"
        );
        assert_eq!(reloaded.algorithms, state.algorithms, "{name} switches");
        assert_eq!(reloaded.policy, state.policy, "{name} policy");
        assert_eq!(reloaded.revision, state.revision, "{name} revision");
        assert_eq!(
            fs::read_to_string(&path).unwrap().trim_end_matches('\n'),
            golden.trim_end_matches('\n'),
            "{name} is rewritten byte for byte"
        );
    }
}

/// `control/limits.properties`: the values both sides of the control file share.
fn limits() -> std::collections::BTreeMap<String, String> {
    let text = fs::read_to_string(contracts().join("control/limits.properties")).unwrap();
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once('=')
                .unwrap_or_else(|| panic!("not key=value: {l}"));
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect()
}

/// The agents ignore a control file larger than the contract's limit, so the daemon must not
/// write one: its constant is the contract value.
#[test]
fn the_daemons_control_size_limit_is_the_contract_value() {
    assert_eq!(
        limits()["max_control_bytes"],
        crate::control::MAX_CONTROL_BYTES.to_string(),
        "MAX_CONTROL_BYTES in control.rs against control/limits.properties"
    );
}

/// `control/hand-edited/*.json`: documents an operator edited by hand to a spelling of the mode
/// the agents accept. The daemon must read each one as the manifest says (not reinitialise it)
/// and write the canonical word the next time it writes the file.
#[test]
fn the_daemon_reads_the_hand_edited_control_documents_and_writes_the_canonical_mode() {
    let dir = contracts().join("control/hand-edited");
    let text = fs::read_to_string(dir.join("expected.properties")).unwrap();
    let manifest: std::collections::BTreeMap<String, String> = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l
                .split_once('=')
                .unwrap_or_else(|| panic!("not key=value: {l}"));
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect();
    let documents = json_names(&dir);
    let in_manifest: BTreeSet<String> = manifest
        .keys()
        .filter_map(|k| k.strip_suffix(".mode").map(str::to_string))
        .collect();
    assert_eq!(
        in_manifest, documents,
        "expected.properties against hand-edited/*.json"
    );
    assert!(
        documents.len() >= 10,
        "the spellings are there: {documents:?}"
    );

    let names = |value: &str| -> Vec<String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    };
    for name in &documents {
        let work = tempfile::tempdir().unwrap();
        let path = work.path().join("control.json");
        fs::copy(dir.join(format!("{name}.json")), &path).unwrap();
        let original: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

        // A reinitialised file would hold the default mode and revision 1; every document here
        // has a higher revision, so a wiped document shows.
        let ctrl = Controller::load_or_init(&path, Mode::Off).unwrap();

        let state = ctrl.snapshot();
        assert_eq!(
            state.mode.as_str(),
            manifest[&format!("{name}.mode")],
            "{name} mode"
        );
        assert_eq!(
            state.revision.to_string(),
            manifest[&format!("{name}.revision")],
            "{name} revision"
        );
        for (want, field) in [(false, "disabled"), (true, "enabled")] {
            let listed = names(&manifest[&format!("{name}.{field}")]);
            let held: Vec<String> = state
                .algorithms
                .iter()
                .filter(|(_, enabled)| **enabled == want)
                .map(|(n, _)| n.clone())
                .collect();
            assert_eq!(held, listed, "{name} {field} switches");
        }
        // `outside_request`: a word the agents accept is written back canonical; absent, or a
        // value nobody accepts (the agents keep what they had), is written as the default.
        let outside = &manifest[&format!("{name}.outside_request")];
        let canonical = if outside == "unknown" {
            "block"
        } else {
            outside.as_str()
        };
        assert_eq!(
            state.outside_request.as_str(),
            canonical,
            "{name} outside_request"
        );
        // Rewritten with the canonical words and nothing else changed.
        let written: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            written["mode"],
            manifest[&format!("{name}.mode")].as_str(),
            "{name} rewritten mode"
        );
        assert_eq!(
            written["outside_request"], canonical,
            "{name} rewritten outside_request"
        );
        for field in ["algorithms", "revision", "updated_at"] {
            assert_eq!(written[field], original[field], "{name} {field} kept");
        }
    }
}

fn json_names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".json").map(str::to_string)
        })
        .collect()
}

// ---- events ---------------------------------------------------------------

/// When the daemon ingested the line, in every parsed event of these tests.
const RECEIVED_AT: &str = "2026-06-06T12:00:01Z";

/// What the daemon reads from one golden event line.
struct Expect {
    file: &'static str,
    /// The `kind` the line has or the daemon infers from its `event` member.
    kind: &'static str,
    hook: &'static str,
    algorithm: &'static str,
    action: &'static str,
    confidence: i64,
    latency_us: Option<i64>,
    /// The `timestamp` the daemon parsed, as RFC 3339: a string as written, the backports'
    /// epoch milliseconds converted. Empty for a line with none, such as a start line.
    timestamp: &'static str,
    severity: &'static str,
    /// What the daemon does with the line: only a detection is counted, logged and uploaded.
    class: EventClass,
}

#[rustfmt::skip]
fn expectations() -> Vec<Expect> {
    use EventClass::{Detection, Diagnostic, Lifecycle, Telemetry};
    let e = |file, kind, hook, algorithm, action, confidence, latency_us, timestamp, severity, class| Expect {
        file, kind, hook, algorithm, action, confidence, latency_us, timestamp, severity, class,
    };
    let at = "2026-01-01T00:00:00Z";
    vec![
        e("primary/detection-block-request.json", "detection", "writeFile", "writeFile_script", "block", 90, Some(1234), at, "critical", Detection),
        e("primary/detection-monitor-no-request.json", "detection", "ssrf", "ssrf_aws", "log", 100, Some(1234), at, "critical", Detection),
        // The strings that mark a diagnostic, inside the escaped data of a detection: still a detection.
        e("primary/detection-reserved-strings.json", "detection", "ssrf", "ssrf_obfuscate", "log", 70, Some(1234), at, "medium", Detection),
        e("primary/telemetry.json", "telemetry", "http_request", "hook_latency", "observe", 0, Some(1234), at, "low", Telemetry),
        // The backports write `"event":"ohmyrasp-detection"` and no `kind`, and the time as epoch
        // milliseconds.
        e("backport/detection-block-request.json", "detection", "ProcessBuilder.start", "javaN_command_execution_shell_meta", "block", 85, None, at, "high", Detection),
        e("backport/detection-monitor-no-request.json", "detection", "ProcessBuilder.start", "javaN_command_execution_exploit_primitive", "log", 95, None, at, "critical", Detection),
        e("backport/detection-reserved-strings.json", "detection", "ProcessBuilder.start", "javaN_command_execution_exploit_primitive", "log", 95, None, at, "critical", Detection),
        e("backport/telemetry.json", "telemetry", "http_request", "hook_latency", "observe", 0, Some(1234), at, "low", Telemetry),
        // The start line has no `kind` and no `timestamp`: the daemon reads it from its `event`
        // member as a lifecycle line, which is not a detection.
        e("backport/agent-start-java8.json", "lifecycle", "", "", "", 0, None, "", "low", Lifecycle),
        e("backport/agent-start-java11.json", "lifecycle", "", "", "", 0, None, "", "low", Lifecycle),
        e("backport/agent-start-java17.json", "lifecycle", "", "", "", 0, None, "", "low", Lifecycle),
        // A hook that did not apply, and the line that says no more are written: no `algorithm` or
        // `action`, so neither is a detection. The backports name them in `event`, not `kind`.
        e("primary/diagnostic-hook-miss.json", "diagnostic", "", "", "", 0, None, at, "low", Diagnostic),
        e("primary/diagnostic-hook-miss-suppressed.json", "diagnostic", "", "", "", 0, None, at, "low", Diagnostic),
        e("backport/hook-miss.json", "diagnostic", "", "", "", 0, None, at, "low", Diagnostic),
        e("backport/hook-miss-suppressed.json", "diagnostic", "", "", "", 0, None, at, "low", Diagnostic),
    ]
}

fn golden_events() -> Vec<(String, String)> {
    let mut found = Vec::new();
    for dir in ["primary", "backport"] {
        let path = contracts().join("events").join(dir);
        let mut names: Vec<_> = fs::read_dir(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".json"))
            .collect();
        names.sort();
        for name in names {
            let text = fs::read_to_string(path.join(&name)).unwrap();
            let line = text.strip_suffix('\n').unwrap_or(&text);
            assert!(!line.contains('\n'), "events/{dir}/{name} is one line");
            found.push((format!("{dir}/{name}"), line.to_string()));
        }
    }
    found
}

fn identity() -> CloudIdentity {
    CloudIdentity {
        app_id: "app1".into(),
        environment_id: "env1".into(),
        agent_id: "agent1".into(),
        policy_id: Some("pol1".into()),
        policy_version: 3,
    }
}

#[test]
fn every_golden_event_line_parses_to_what_the_daemon_reads() {
    let expectations = expectations();
    let events = golden_events();
    let listed: BTreeSet<&str> = expectations.iter().map(|e| e.file).collect();
    let on_disk: BTreeSet<&str> = events.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        on_disk, listed,
        "events/** against the expectations in contract_tests.rs"
    );

    for (name, line) in &events {
        let want = expectations.iter().find(|e| e.file == name).unwrap();
        let event = AgentEvent::parse_line(7, RECEIVED_AT.into(), line)
            .unwrap_or_else(|| panic!("{name}: the daemon rejects the line"));
        assert_eq!(event.kind, want.kind, "{name} kind");
        assert_eq!(event.hook, want.hook, "{name} hook");
        assert_eq!(event.algorithm, want.algorithm, "{name} algorithm");
        assert_eq!(event.action, want.action, "{name} action");
        assert_eq!(event.confidence, want.confidence, "{name} confidence");
        assert_eq!(event.latency_us, want.latency_us, "{name} latency_us");
        assert_eq!(event.timestamp, want.timestamp, "{name} timestamp");
        assert_eq!(event.severity(), want.severity, "{name} severity");
        assert_eq!(event.class(), want.class, "{name} class");
        assert_eq!(
            event.is_detection(),
            want.class == EventClass::Detection,
            "{name} is_detection"
        );
        assert_eq!(event.is_block(), want.action == "block", "{name} is_block");
        assert_eq!(
            event.raw,
            serde_json::from_str::<Value>(line).unwrap(),
            "{name} raw line kept verbatim"
        );
    }
}

/// The writers escape what an application controls, so the strings the daemon reads at the top level
/// to recognise a diagnostic (`"kind":"diagnostic"`, `"event":"ohmyrasp-hook-miss"`) can only be
/// inside a string of a detection. The two fixtures hold them there, written by the real writers;
/// the daemon reads their top level only and keeps them detections, recorded and uploaded.
#[test]
fn reserved_strings_inside_escaped_detection_data_do_not_make_a_diagnostic() {
    for name in [
        "primary/detection-reserved-strings.json",
        "backport/detection-reserved-strings.json",
    ] {
        let (_, line) = golden_events()
            .into_iter()
            .find(|(file, _)| file == name)
            .unwrap_or_else(|| panic!("{name} is missing"));
        for reserved in [
            r#"\"kind\":\"diagnostic\""#,
            r#"\"event\":\"ohmyrasp-hook-miss\""#,
            r#"\"diagnostic\":\"hook_miss\""#,
        ] {
            assert!(
                line.contains(reserved),
                "{name} holds {reserved} inside a string of the detection: {line}"
            );
        }
        let event = AgentEvent::parse_line(7, RECEIVED_AT.into(), &line).unwrap();
        assert_eq!(event.class(), EventClass::Detection, "{name}");
        assert!(
            event.raw.get("diagnostic").is_none(),
            "{name}: no top-level member"
        );
        assert_ne!(
            event.raw.get("kind").and_then(Value::as_str),
            Some("diagnostic"),
            "{name}"
        );

        let store = EventStore::new(10);
        let mut offered = 0;
        crate::route(event, &store, |_| offered += 1);
        let stats = store.stats();
        assert_eq!(
            (offered, stats.detections, stats.retained),
            (1, 1, 1),
            "{name}"
        );
        assert_eq!(stats.diagnostics, 0, "{name}");
    }
}

/// What the daemon uploads for each detection: the fields it forwards, and nothing the agent
/// redacted. Telemetry is never uploaded (`main.rs` routes it to the latency panel only).
#[test]
fn every_golden_detection_uploads_the_body_the_daemon_builds() {
    let (properties, required) = security_event_input_schema();
    let expectations = expectations();
    for (name, line) in golden_events() {
        let event = AgentEvent::parse_line(7, RECEIVED_AT.into(), &line).unwrap();
        if !event.is_detection() {
            continue;
        }
        let want = expectations.iter().find(|e| e.file == name).unwrap();
        let body = event.to_cloud_attack(&identity());
        let raw: Value = serde_json::from_str(&line).unwrap();

        // The body is a SecurityEventInput of api/api/openapi.yaml.
        let keys: BTreeSet<String> = body.as_object().unwrap().keys().cloned().collect();
        assert!(
            keys.is_subset(&properties),
            "{name}: body members {keys:?} are all in the schema {properties:?}"
        );
        assert!(
            required.is_subset(&keys),
            "{name}: the schema's required members {required:?} are all in {keys:?}"
        );

        assert_eq!(
            body["hook"],
            raw["hook"].as_str().unwrap_or(""),
            "{name} hook"
        );
        assert_eq!(
            body["algorithm"],
            raw["algorithm"].as_str().unwrap_or(""),
            "{name} algorithm"
        );
        let message = raw["message"]
            .as_str()
            .filter(|m| !m.is_empty())
            .unwrap_or("agent event");
        assert_eq!(body["message"], message, "{name} message");
        // Every detection line has a time, so `occurred_at` is the time the agent wrote and not
        // the time the daemon read the line.
        assert_eq!(body["occurred_at"], want.timestamp, "{name} occurred_at");
        assert_ne!(body["occurred_at"], RECEIVED_AT, "{name} occurred_at");

        let attributes = body["attributes"].as_object().unwrap();
        assert_eq!(
            attributes["action"],
            raw["action"].as_str().unwrap_or(""),
            "{name} action"
        );
        assert_eq!(
            attributes["confidence"],
            raw["confidence"].as_i64().unwrap_or(0),
            "{name} confidence"
        );
        assert_eq!(
            attributes.get("latency_us"),
            raw.get("latency_us"),
            "{name} latency_us"
        );
        for (key, value) in raw
            .get("details")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            assert_eq!(
                attributes[&format!("detail.{key}")],
                *value,
                "{name} detail.{key}"
            );
        }
        for key in ["method", "uri", "query"] {
            assert_eq!(
                attributes.get(&format!("request.{key}")),
                raw.get("request").and_then(|r| r.get(key)),
                "{name} request.{key}"
            );
        }
        // Parameters and headers stay local: only the method, URI and query string are forwarded.
        let members: BTreeSet<&String> = attributes
            .keys()
            .filter(|k| k.starts_with("request."))
            .collect();
        assert!(
            members
                .iter()
                .all(|k| ["request.method", "request.uri", "request.query"].contains(&k.as_str())),
            "{name}: {members:?}"
        );
    }
}

/// What the pipeline does with each golden line: a detection is recorded and offered to the
/// uploader once; telemetry feeds the latency panel; a start line only describes the agent; a
/// diagnostic is kept in the local status view. A start line or a diagnostic is never a
/// detection, so it is not counted and not uploaded.
#[test]
fn only_golden_detections_are_recorded_and_offered_to_the_uploader() {
    let expectations = expectations();
    for (name, line) in golden_events() {
        let want = expectations.iter().find(|e| e.file == name).unwrap();
        let store = EventStore::new(10);
        let mut offered = Vec::new();
        let event = AgentEvent::parse_line(7, RECEIVED_AT.into(), &line).unwrap();
        crate::route(event, &store, |event| offered.push(event));

        let stats = store.stats();
        let is_detection = want.class == EventClass::Detection;
        assert_eq!(offered.len(), usize::from(is_detection), "{name} offered");
        assert_eq!(
            stats.detections,
            u64::from(is_detection),
            "{name} detections"
        );
        assert_eq!(stats.total, u64::from(is_detection), "{name} total");
        assert_eq!(
            stats.retained,
            usize::from(is_detection),
            "{name} attack log"
        );
        assert_eq!(
            stats.blocks,
            u64::from(is_detection && want.action == "block"),
            "{name} blocks"
        );
        assert_eq!(
            stats.telemetry,
            u64::from(want.class == EventClass::Telemetry),
            "{name} telemetry"
        );
        assert!(stats.ignored_kinds.is_empty(), "{name} is a known kind");
        // A diagnostic is counted in the status view; the suppressed line only sets the flag.
        let is_diagnostic = want.class == EventClass::Diagnostic;
        let suppressed = name.contains("suppressed");
        assert_eq!(
            stats.diagnostics,
            u64::from(is_diagnostic),
            "{name} diagnostics"
        );
        assert_eq!(
            stats.hook_misses.len(),
            usize::from(is_diagnostic && !suppressed),
            "{name} hook_misses"
        );
        assert_eq!(
            stats.hook_misses_suppressed,
            is_diagnostic && suppressed,
            "{name} hook_misses_suppressed"
        );
        assert_eq!(stats.hook_misses_dropped, 0, "{name} hook_misses_dropped");
        if want.class == EventClass::Lifecycle {
            let agent = stats
                .agent
                .unwrap_or_else(|| panic!("{name}: no agent entry"));
            assert_eq!(
                agent.line,
                name.trim_start_matches("backport/agent-start-")
                    .trim_end_matches(".json")
            );
            assert_eq!(agent.java_version, "1.8.0_402", "{name} java_version");
            assert_eq!(agent.seen_at, RECEIVED_AT, "{name} seen_at");
        } else {
            assert!(
                stats.agent.is_none(),
                "{name}: only a start line describes the agent"
            );
        }
    }
}

/// The two writers' hook-miss lines say the same thing to the daemon, apart from the unit's line
/// token (`SqlHookModule` on the primary agent, `JavaNJdbcTransformer` on a backport agent), and
/// the suppressed lines are told apart from them.
#[test]
fn the_two_writers_hook_miss_lines_read_the_same() {
    let events: std::collections::BTreeMap<String, String> = golden_events().into_iter().collect();
    let read = |name: &str| {
        AgentEvent::parse_line(7, RECEIVED_AT.into(), &events[name])
            .unwrap_or_else(|| panic!("{name}: the daemon rejects the line"))
    };
    let primary = read("primary/diagnostic-hook-miss.json");
    let backport = read("backport/hook-miss.json");
    let (p, b) = (primary.hook_miss().unwrap(), backport.hook_miss().unwrap());
    assert_eq!(p.format, DiagnosticFormat::Primary);
    assert_eq!(b.format, DiagnosticFormat::Backport);
    assert_eq!(p.unit, "SqlHookModule");
    assert_eq!(b.unit, "JavaNJdbcTransformer");
    for miss in [&p, &b] {
        assert_eq!(
            miss.class,
            "org.apache.ibatis.executor.statement.BaseStatementHandler"
        );
        assert_eq!(miss.reason, "no_agent_call");
        assert_eq!(miss.exception, None);
        assert_eq!(
            miss.looked_for,
            ["prepare(Ljava/sql/Connection;Ljava/lang/Integer;)Ljava/sql/Statement;"]
        );
        assert_eq!(
            miss.found,
            ["prepare(Ljava/sql/Connection;Ljava/time/Duration;)Ljava/sql/Statement;"]
        );
        assert_eq!(miss.code_source.as_deref(), Some("mybatis-9.9.9.jar"));
        assert_eq!(
            miss.code_source_path.as_deref(),
            Some("/opt/app/lib/mybatis-9.9.9.jar")
        );
        assert_eq!(miss.implementation_version.as_deref(), Some("9.9.9"));
    }
    assert!(!primary.is_hook_miss_suppressed() && !backport.is_hook_miss_suppressed());

    for name in [
        "primary/diagnostic-hook-miss-suppressed.json",
        "backport/hook-miss-suppressed.json",
    ] {
        let event = read(name);
        assert!(event.is_hook_miss_suppressed(), "{name}");
        assert!(event.hook_miss().is_none(), "{name}");
        assert_eq!(event.raw["limit"], 32, "{name} limit");
    }
}

/// The redaction the agent applies to `parameters` and `headers` reaches the daemon intact and is
/// not undone on the way to the cloud.
#[test]
fn the_redacted_request_is_not_uploaded_with_its_secrets() {
    let line = golden_events()
        .into_iter()
        .find(|(n, _)| n == "primary/detection-block-request.json")
        .unwrap()
        .1;
    let event = AgentEvent::parse_line(7, RECEIVED_AT.into(), &line).unwrap();
    let request = &event.raw["request"];
    assert_eq!(
        request["parameters"]["password"],
        serde_json::json!(["[redacted]"])
    );
    assert_eq!(request["headers"]["authorization"], "Bearer [redacted]");
    assert_eq!(request["headers"]["cookie"], "[redacted]");

    let uploaded = event.to_cloud_attack(&identity()).to_string();
    assert!(
        !uploaded.contains("eyJhbGci"),
        "the bearer token is not uploaded"
    );
    assert!(
        !uploaded.contains("JSESSIONID"),
        "the cookie is not uploaded"
    );
    // The agent redacts the values of sensitive parameters inside the query string as well, so
    // the `request.query` the daemon uploads has the marker where the password was.
    assert_eq!(
        event.to_cloud_attack(&identity())["attributes"]["request.query"],
        "folder=reports&password=[redacted]"
    );
    assert!(
        !uploaded.contains("hunter2"),
        "the password in the query string is not uploaded"
    );
}

/// The members and required members of `SecurityEventInput` in `api/api/openapi.yaml`, the
/// schema of `POST /api/v1/events/attack`. No test of the API posts the daemon's body, so this
/// is the one place the two are compared.
fn security_event_input_schema() -> (BTreeSet<String>, BTreeSet<String>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../api/api/openapi.yaml");
    let text = fs::read_to_string(&path).unwrap();
    let mut lines = text.lines().skip_while(|l| *l != "    SecurityEventInput:");
    lines.next().expect("SecurityEventInput is in openapi.yaml");
    let (mut properties, mut required) = (BTreeSet::new(), BTreeSet::new());
    for line in lines.take_while(|l| l.starts_with("      ")) {
        if let Some(list) = line.trim().strip_prefix("required: [") {
            required.extend(
                list.trim_end_matches(']')
                    .split(',')
                    .map(|s| s.trim().to_string()),
            );
        } else if line.starts_with("        ")
            && !line.starts_with("         ")
            && let Some((name, _)) = line.trim().split_once(':')
        {
            properties.insert(name.to_string());
        }
    }
    assert!(
        properties.contains("severity") && required.contains("message"),
        "parsed {properties:?} {required:?}"
    );
    (properties, required)
}
