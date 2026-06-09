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

use serde::Serialize;
use serde_json::{Map, Value, json};

/// One ingested agent event.
#[derive(Debug, Clone, Serialize)]
pub struct AgentEvent {
    /// Daemon-assigned monotonic sequence number.
    pub seq: u64,
    /// RFC3339 timestamp of when the daemon ingested the line.
    pub received_at: String,
    /// `"detection"` (default) or `"telemetry"`.
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
            kind: str_field(&raw, "kind").unwrap_or_else(|| "detection".into()),
            timestamp: str_field(&raw, "timestamp").unwrap_or_default(),
            hook: str_field(&raw, "hook").unwrap_or_default(),
            algorithm: str_field(&raw, "algorithm").unwrap_or_default(),
            action: str_field(&raw, "action").unwrap_or_default(),
            confidence: int_field(&raw, "confidence").unwrap_or(0),
            message: str_field(&raw, "message").unwrap_or_default(),
            latency_us: int_field(&raw, "latency_us"),
            raw,
        })
    }

    /// True when this event represents a security detection (vs pure telemetry).
    pub fn is_detection(&self) -> bool {
        self.kind != "telemetry"
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
        body.insert("environment_id".into(), Value::String(ident.environment_id.clone()));
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
            Value::String(if self.message.is_empty() { "agent event".into() } else { self.message.clone() }),
        );
        body.insert(
            "occurred_at".into(),
            Value::String(if self.timestamp.is_empty() { self.received_at.clone() } else { self.timestamp.clone() }),
        );
        body.insert("attributes".into(), Value::Object(attributes));
        Value::Object(body)
    }
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
}
