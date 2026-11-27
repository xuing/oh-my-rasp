//! Event model: the daemon-internal representation of a Java-agent event and
//! its translation to the cloud control-plane wire format.
//!
//! The agent writes one JSON object per line via its `JsonEventLogger`. The
//! canonical detection shape is:
//!
//! ```json
//! {
//!   "timestamp": "2026-06-06T12:00:00Z",
//!   "hook": "ProcessBuilder.start",
//!   "algorithm": "command_injection",
//!   "action": "block",
//!   "confidence": 95,
//!   "message": "...",
//!   "request": { "method": "...", "uri": "...", "query": "...",
//!                "parameters": {...}, "headers": {...} },
//!   "details": { ... }
//! }
//! ```
//!
//! Newer agents additionally emit `kind` ("detection" | "telemetry") and
//! `latency_us` (the in-hook detection latency). Every field is optional here:
//! the daemon never rejects a line for missing structure, and the full original
//! object is retained verbatim in [`AgentEvent::raw`] so the console can show it
//! exactly as produced.
//!
//! Agents already deployed write other shapes, which [`AgentEvent::parse_line`]
//! reads as they are: a detection with an `event` member
//! (`"event":"ohmyrasp-detection"`), no `kind` and a numeric epoch-millisecond
//! `timestamp`, and a start line (`"event":"ohmyrasp-java8-agent-start"`) that is
//! not a detection. See [`EventClass`] for how a line is classified.

use serde::Serialize;
use serde_json::{Map, Value, json};

/// What a line is, as far as the daemon is concerned. Only a [`Detection`](Self::Detection) is
/// recorded as an attack and offered to the uploader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventClass {
    /// A security detection: the attack log, the detection counters and the upload.
    Detection,
    /// A latency sample: the latency panel only.
    Telemetry,
    /// An agent lifecycle line (the start line): the agent entry of the local status view only.
    Lifecycle,
    /// Any other `kind` (a later agent version adds diagnostic kinds), or a line that says
    /// nothing the daemon can classify: counted per kind, never recorded as a detection, never
    /// uploaded.
    Ignored,
}

/// One ingested agent event.
#[derive(Debug, Clone, Serialize)]
pub struct AgentEvent {
    /// Daemon-assigned monotonic sequence number.
    pub seq: u64,
    /// RFC3339 timestamp of when the daemon ingested the line.
    pub received_at: String,
    /// The line's `kind`; when it has none, the kind inferred from its `event` member and fields:
    /// `"detection"`, `"lifecycle"`, or `"unknown"`. Any value is kept as written.
    pub kind: String,
    pub timestamp: String,
    pub hook: String,
    pub algorithm: String,
    pub action: String,
    pub confidence: i64,
    pub message: String,
    /// In-hook detection latency in microseconds, when reported.
    pub latency_us: Option<i64>,
    /// The full original line, parsed but otherwise untouched.
    pub raw: Value,
}

impl AgentEvent {
    /// Parse one NDJSON line into an event. Returns `None` for blank lines or
    /// lines that are not a JSON object.
    pub fn parse_line(seq: u64, received_at: String, line: &str) -> Option<Self> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        let raw: Value = serde_json::from_str(trimmed).ok()?;
        if !raw.is_object() {
            return None;
        }
        Some(Self {
            seq,
            received_at,
            kind: kind_field(&raw),
            timestamp: timestamp_field(&raw),
            hook: str_field(&raw, "hook").unwrap_or_default(),
            algorithm: str_field(&raw, "algorithm").unwrap_or_default(),
            action: str_field(&raw, "action").unwrap_or_default(),
            confidence: int_field(&raw, "confidence").unwrap_or(0),
            message: str_field(&raw, "message").unwrap_or_default(),
            latency_us: int_field(&raw, "latency_us"),
            raw,
        })
    }

    /// How the daemon treats this line; see [`EventClass`].
    pub fn class(&self) -> EventClass {
        match self.kind.as_str() {
            "detection" => EventClass::Detection,
            "telemetry" => EventClass::Telemetry,
            "lifecycle" => EventClass::Lifecycle,
            _ => EventClass::Ignored,
        }
    }

    /// True when this event is a security detection: not telemetry, not a lifecycle line and
    /// not a kind the daemon does not know.
    pub fn is_detection(&self) -> bool {
        self.class() == EventClass::Detection
    }

    /// For an ignored line, the label its counter is kept under: the `kind`, else the `event`.
    pub fn ignored_label(&self) -> String {
        match str_field(&self.raw, "event") {
            Some(event) if self.kind == "unknown" => format!("event:{event}"),
            _ => self.kind.clone(),
        }
    }

    /// What a lifecycle line says about the agent: its line (`java8`, `java11`, `java17`; absent
    /// when the line's `event` has another shape) and the JVM it runs in.
    pub fn agent_info(&self) -> AgentInfo {
        let line = str_field(&self.raw, "event")
            .and_then(|e| {
                e.strip_prefix("ohmyrasp-")
                    .and_then(|rest| rest.strip_suffix("-agent-start"))
                    .map(str::to_string)
            })
            .unwrap_or_default();
        AgentInfo {
            line,
            java_version: str_field(&self.raw, "java_version").unwrap_or_default(),
            java_vendor: str_field(&self.raw, "java_vendor").unwrap_or_default(),
            seen_at: self.received_at.clone(),
        }
    }

    /// True when the agent blocked the request for this event.
    pub fn is_block(&self) -> bool {
        self.action.eq_ignore_ascii_case("block")
    }

    /// Map confidence to the control-plane severity bucket (mirrors the Java
    /// `ControlPlaneClient.severity`).
    pub fn severity(&self) -> &'static str {
        match self.confidence {
            c if c >= 90 => "critical",
            c if c >= 75 => "high",
            c if c >= 50 => "medium",
            _ => "low",
        }
    }

    /// Build the `/events/attack` request body, enriching the agent event with
    /// the cloud identity owned by the daemon.
    pub fn to_cloud_attack(&self, ident: &CloudIdentity) -> Value {
        let mut attributes = Map::new();
        attributes.insert("action".into(), Value::String(self.action.clone()));
        attributes.insert("confidence".into(), json!(self.confidence));
        if let Some(latency) = self.latency_us {
            attributes.insert("latency_us".into(), json!(latency));
        }
        // Flatten the agent's `details` map as `detail.<k>` attributes.
        if let Some(details) = self.raw.get("details").and_then(Value::as_object) {
            for (k, v) in details {
                attributes.insert(format!("detail.{k}"), v.clone());
            }
        }
        // Carry the request context, when the detection had an active request.
        if let Some(request) = self.raw.get("request").and_then(Value::as_object) {
            for key in ["method", "uri", "query"] {
                if let Some(v) = request.get(key) {
                    attributes.insert(format!("request.{key}"), v.clone());
                }
            }
        }

        let mut body = Map::new();
        body.insert("application_id".into(), Value::String(ident.app_id.clone()));
        body.insert(
            "environment_id".into(),
            Value::String(ident.environment_id.clone()),
        );
        body.insert("agent_id".into(), Value::String(ident.agent_id.clone()));
        if let Some(policy_id) = &ident.policy_id {
            body.insert("policy_id".into(), Value::String(policy_id.clone()));
            if ident.policy_version > 0 {
                body.insert("policy_version".into(), json!(ident.policy_version));
            }
        }
        body.insert("hook".into(), Value::String(self.hook.clone()));
        body.insert("algorithm".into(), Value::String(self.algorithm.clone()));
        body.insert("severity".into(), Value::String(self.severity().into()));
        body.insert(
            "message".into(),
            Value::String(if self.message.is_empty() {
                "agent event".into()
            } else {
                self.message.clone()
            }),
        );
        body.insert(
            "occurred_at".into(),
            Value::String(if self.timestamp.is_empty() {
                self.received_at.clone()
            } else {
                self.timestamp.clone()
            }),
        );
        body.insert("attributes".into(), Value::Object(attributes));
        Value::Object(body)
    }
}

/// The agent as its last lifecycle (start) line described it, for the local status view.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AgentInfo {
    /// `java8`, `java11` or `java17`; empty when the line does not say.
    pub line: String,
    pub java_version: String,
    pub java_vendor: String,
    /// When the daemon read the line.
    pub seen_at: String,
}

/// Cloud identity assigned during registration and refreshed by heartbeats.
#[derive(Debug, Clone, Default)]
pub struct CloudIdentity {
    pub app_id: String,
    pub environment_id: String,
    pub agent_id: String,
    pub policy_id: Option<String>,
    pub policy_version: i64,
}

/// The kind of a line that has no `kind`. The backport agents write a start line
/// (`ohmyrasp-<line>-agent-start`) and detections with `"event":"ohmyrasp-detection"`; an older
/// primary agent wrote detections with neither. A line with an `algorithm` and an `action` is a
/// detection; anything else says nothing the daemon can classify.
fn infer_kind(raw: &Value) -> &'static str {
    let event = str_field(raw, "event");
    if let Some(event) = &event
        && event.starts_with("ohmyrasp-")
        && event.ends_with("-agent-start")
    {
        return "lifecycle";
    }
    let has = |key: &str| str_field(raw, key).is_some_and(|v| !v.is_empty());
    if event.as_deref() == Some("ohmyrasp-detection") || (has("algorithm") && has("action")) {
        "detection"
    } else {
        "unknown"
    }
}

/// The label an ignored line is counted under when its `kind` is present but not a string.
pub const NON_STRING_KIND: &str = "(non-string)";

/// The `kind` as written, or inferred when the line has none. A `kind` that is present and not a
/// string is a writer saying something the daemon cannot read: it is never inferred from the other
/// members, which would let a malformed line pass as a detection.
fn kind_field(raw: &Value) -> String {
    match raw.get("kind") {
        Some(Value::String(kind)) => kind.clone(),
        Some(_) => NON_STRING_KIND.to_string(),
        None => infer_kind(raw).into(),
    }
}

/// The `timestamp` as an RFC 3339 string: a string as written, a number as epoch milliseconds.
/// Empty when the line has none or the value cannot be read, so the daemon's read time stands in.
fn timestamp_field(raw: &Value) -> String {
    match raw.get("timestamp") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| {
                number
                    .as_f64()
                    .filter(|f| f.is_finite())
                    .map(|f| f.floor() as i64)
            })
            .and_then(crate::util::epoch_millis_rfc3339)
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn str_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn int_field(value: &Value, key: &str) -> Option<i64> {
    let v = value.get(key)?;
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `kind` that is not a string is not a detection, whatever else the line carries.
    #[test]
    fn a_kind_that_is_not_a_string_is_ignored_and_not_inferred() {
        for kind in ["5", "null", "true", "[\"detection\"]", "{\"a\":1}"] {
            let line = format!(
                r#"{{"kind":{kind},"event":"ohmyrasp-detection","hook":"h","algorithm":"a","action":"block"}}"#
            );
            let ev = AgentEvent::parse_line(1, "t".into(), &line).expect("parsed");
            assert_eq!(ev.class(), EventClass::Ignored, "kind {kind}");
            assert!(!ev.is_detection(), "kind {kind}");
            assert_eq!(ev.ignored_label(), NON_STRING_KIND, "kind {kind}");
        }
        // No `kind` at all is still inferred, as older agents rely on.
        let kindless = r#"{"hook":"h","algorithm":"a","action":"block"}"#;
        let ev = AgentEvent::parse_line(1, "t".into(), kindless).expect("parsed");
        assert!(ev.is_detection());
    }

    #[test]
    fn parses_canonical_detection() {
        let line = r#"{"timestamp":"2026-06-06T12:00:00Z","hook":"ProcessBuilder.start","algorithm":"command_injection","action":"block","confidence":95,"message":"rce","request":{"method":"POST","uri":"/x","query":"a=1","parameters":{},"headers":{}},"details":{"command":"id"}}"#;
        let ev = AgentEvent::parse_line(1, "2026-06-06T12:00:01Z".into(), line).expect("parsed");
        assert_eq!(ev.hook, "ProcessBuilder.start");
        assert_eq!(ev.algorithm, "command_injection");
        assert!(ev.is_block());
        assert!(ev.is_detection());
        assert_eq!(ev.severity(), "critical");
    }

    #[test]
    fn skips_blank_and_non_object() {
        assert!(AgentEvent::parse_line(1, "t".into(), "   ").is_none());
        assert!(AgentEvent::parse_line(1, "t".into(), "[1,2,3]").is_none());
        assert!(AgentEvent::parse_line(1, "t".into(), "not json").is_none());
    }

    #[test]
    fn enriches_cloud_attack_body() {
        let line = r#"{"hook":"sql","algorithm":"sqli","action":"log","confidence":60,"message":"m","details":{"q":"' or 1=1"},"request":{"method":"GET","uri":"/a","query":"id=1"}}"#;
        let ev = AgentEvent::parse_line(7, "2026-06-06T00:00:00Z".into(), line).unwrap();
        let ident = CloudIdentity {
            app_id: "app1".into(),
            environment_id: "env1".into(),
            agent_id: "agent1".into(),
            policy_id: Some("pol1".into()),
            policy_version: 3,
        };
        let body = ev.to_cloud_attack(&ident);
        assert_eq!(body["application_id"], json!("app1"));
        assert_eq!(body["agent_id"], json!("agent1"));
        assert_eq!(body["severity"], json!("medium"));
        assert_eq!(body["policy_version"], json!(3));
        assert_eq!(body["attributes"]["detail.q"], json!("' or 1=1"));
        assert_eq!(body["attributes"]["request.uri"], json!("/a"));
    }

    #[test]
    fn latency_is_extracted_and_telemetry_recognised() {
        let line = r#"{"kind":"telemetry","hook":"sql","algorithm":"sqli","action":"log","confidence":0,"latency_us":42}"#;
        let ev = AgentEvent::parse_line(1, "t".into(), line).unwrap();
        assert_eq!(ev.latency_us, Some(42));
        assert!(!ev.is_detection());
    }

    fn parse(line: &str) -> AgentEvent {
        AgentEvent::parse_line(1, "2026-06-06T12:00:01Z".into(), line).expect("parsed")
    }

    #[test]
    fn a_line_without_kind_is_classified_by_its_event_member() {
        for line in ["java8", "java11", "java17"] {
            let ev = parse(&format!(
                r#"{{"event":"ohmyrasp-{line}-agent-start","mode":"premain","java_version":"1.8.0_402"}}"#
            ));
            assert_eq!(ev.class(), EventClass::Lifecycle, "{line} start line");
            assert!(!ev.is_detection());
            assert_eq!(ev.agent_info().line, line);
            assert_eq!(ev.agent_info().java_version, "1.8.0_402");
        }
        let detection = parse(r#"{"event":"ohmyrasp-detection","hook":"h","action":"log"}"#);
        assert_eq!(detection.class(), EventClass::Detection, "event only");
        let older = parse(r#"{"hook":"h","algorithm":"a","action":"block"}"#);
        assert_eq!(older.class(), EventClass::Detection, "algorithm and action");
        // A start line is a lifecycle line even when it carries an action-like member.
        let start = parse(r#"{"event":"ohmyrasp-java8-agent-start","algorithm":"a","action":"b"}"#);
        assert_eq!(start.class(), EventClass::Lifecycle);
    }

    #[test]
    fn a_line_that_says_nothing_the_daemon_knows_is_not_a_detection() {
        let other_event = parse(r#"{"event":"ohmyrasp-java8-agent-shutdown"}"#);
        assert_eq!(other_event.class(), EventClass::Ignored);
        assert_eq!(
            other_event.ignored_label(),
            "event:ohmyrasp-java8-agent-shutdown"
        );
        let bare = parse(r#"{"hook":"h"}"#);
        assert_eq!(bare.class(), EventClass::Ignored);
        assert_eq!(bare.ignored_label(), "unknown");
    }

    #[test]
    fn an_unknown_kind_is_not_a_detection_even_when_it_looks_like_one() {
        let line =
            r#"{"kind":"diagnostic","hook":"h","algorithm":"a","action":"block","confidence":99}"#;
        let ev = parse(line);
        assert_eq!(ev.kind, "diagnostic");
        assert_eq!(ev.class(), EventClass::Ignored);
        assert!(!ev.is_detection());
        assert_eq!(ev.ignored_label(), "diagnostic");
        // The kind decides: a detection-shaped `event` does not override it.
        let ev = parse(r#"{"kind":"diagnostic","event":"ohmyrasp-detection"}"#);
        assert_eq!(ev.class(), EventClass::Ignored);
    }

    #[test]
    fn timestamp_is_a_string_or_epoch_milliseconds() {
        let at = |value: &str| parse(&format!(r#"{{"kind":"detection","timestamp":{value}}}"#));
        assert_eq!(
            at(r#""2026-06-06T12:00:00Z""#).timestamp,
            "2026-06-06T12:00:00Z"
        );
        assert_eq!(at("1767225600000").timestamp, "2026-01-01T00:00:00Z");
        assert_eq!(at("1767225600123").timestamp, "2026-01-01T00:00:00.123Z");
        assert_eq!(at("1767225600000.0").timestamp, "2026-01-01T00:00:00Z");
        assert_eq!(at("0").timestamp, "1970-01-01T00:00:00Z");
        // Unreadable values keep the fallback: an empty timestamp, so `occurred_at` is the read time.
        for bad in ["-1", "1e30", "true", "null", "[1]", "{}"] {
            assert_eq!(at(bad).timestamp, "", "{bad}");
        }
        let ident = CloudIdentity::default();
        let body = at("-1").to_cloud_attack(&ident);
        assert_eq!(body["occurred_at"], "2026-06-06T12:00:01Z");
        let body = at("1767225600000").to_cloud_attack(&ident);
        assert_eq!(body["occurred_at"], "2026-01-01T00:00:00Z");
    }
}
