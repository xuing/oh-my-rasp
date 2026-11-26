//! Tests against the agent-daemon contract fixtures, `java-agent/contracts/agent-daemon/`.
//!
//! The Java agent and this daemon share two files and no code. The fixtures are the one place
//! the format is written down as examples; the Java tests read the same files. See the
//! README beside them for the normalisation rules and for how to regenerate.
//!
//! * `control/*.json` are produced here, by the real [`Controller`], and compared byte for byte.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::control::{ControlState, Controller, Mode};

/// What `updated_at` is replaced with in a golden control document.
const FIXED_UPDATED_AT: &str = "2026-01-01T00:00:00Z";

/// A cloud policy as the control plane serves it: JSON text the daemon passes through verbatim.
const POLICY: &str = r#"{"version":4,"status":"active","canary_percent":100,"rules":[{"algorithm":"sql_userinput","action":"block"}]}"#;

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

fn json_names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".json").map(str::to_string)
        })
        .collect()
}
