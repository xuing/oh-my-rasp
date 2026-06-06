//! Cloud control-plane HTTP client.
//!
//! This is the daemon's port of the Java agent's old `ControlPlaneClient`: the
//! daemon now owns the registration handshake, heartbeats, and policy pulls, and
//! is the only process that talks to the Go control plane. The agent no longer
//! phones home directly.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::Value;

use crate::config::CloudConfig;

const APP_ID_HEADER: &str = "X-OhMyRasp-App-ID";
const APP_SECRET_HEADER: &str = "X-OhMyRasp-App-Secret";

/// Result of a registration or heartbeat: the assigned identity slice.
#[derive(Debug, Clone, Default)]
pub struct Assignment {
    pub agent_id: Option<String>,
    pub policy_id: Option<String>,
    pub policy_version: i64,
}

pub struct CloudClient {
    http: reqwest::Client,
    base: String,
    cfg: CloudConfig,
}

impl CloudClient {
    pub fn new(cfg: CloudConfig) -> Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Ok(v) = HeaderValue::from_str(&cfg.app_id) {
            headers.insert(APP_ID_HEADER, v);
        }
        if let Ok(v) = HeaderValue::from_str(&cfg.app_secret) {
            headers.insert(APP_SECRET_HEADER, v);
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.request_timeout_s.max(1)))
            .connect_timeout(Duration::from_secs(3))
            .default_headers(headers)
            .user_agent("ohmyrasp-daemon")
            .build()
            .context("building HTTP client")?;
        Ok(Self { http, base: normalize_base(&cfg.backend_url), cfg })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Register the host with the control plane and return its assigned identity.
    pub async fn register(&self) -> Result<Assignment> {
        let body = serde_json::json!({
            "environment_id": self.cfg.environment_id,
            "hostname": self.cfg.hostname,
            "runtime": self.cfg.runtime,
            "version": self.cfg.version,
        });
        let resp = self
            .http
            .post(self.url("/agents/register"))
            .json(&body)
            .send()
            .await
            .context("register request")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("register returned {status}: {text}");
        }
        let value: Value = serde_json::from_str(&text).context("parsing register response")?;
        let agent_id = value.get("id").and_then(Value::as_str).map(str::to_string);
        if agent_id.as_deref().unwrap_or("").is_empty() {
            bail!("register response did not include id");
        }
        Ok(assignment_from(agent_id, &value))
    }

    /// Heartbeat for an already-registered agent; returns any updated assignment.
    pub async fn heartbeat(&self, agent_id: &str) -> Result<Assignment> {
        let resp = self
            .http
            .post(self.url(&format!("/agents/{}/heartbeat", encode_segment(agent_id))))
            .json(&serde_json::json!({ "status": "online" }))
            .send()
            .await
            .context("heartbeat request")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("heartbeat returned {status}: {text}");
        }
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        Ok(assignment_from(Some(agent_id.to_string()), &value))
    }

    /// Pull the assigned policy document, if any. Returns `None` on 404.
    /// The daemon distributes it to the agent via the control file.
    pub async fn pull_policy(&self, agent_id: &str) -> Result<Option<String>> {
        let resp = self
            .http
            .get(self.url(&format!("/agents/{}/policy", encode_segment(agent_id))))
            .send()
            .await
            .context("policy request")?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("pull policy returned {status}: {text}");
        }
        Ok(Some(text))
    }

    /// Upload one enriched attack event.
    pub async fn upload_attack(&self, body: &Value) -> Result<()> {
        let resp = self
            .http
            .post(self.url("/events/attack"))
            .json(body)
            .send()
            .await
            .context("upload attack request")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            bail!("upload attack returned {status}: {text}");
        }
        Ok(())
    }
}

fn assignment_from(agent_id: Option<String>, value: &Value) -> Assignment {
    Assignment {
        agent_id,
        policy_id: value
            .get("policy_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        policy_version: value.get("policy_version").and_then(Value::as_i64).unwrap_or(0),
    }
}

/// Normalize a base URL to always end in `/api/v1` with no trailing slash,
/// matching the Java client's `endpoint()` behaviour.
fn normalize_base(raw: &str) -> String {
    let mut base = raw.trim().trim_end_matches('/').to_string();
    if !base.ends_with("/api/v1") {
        base.push_str("/api/v1");
    }
    base
}

/// Percent-encode a path segment's slashes, matching the Java `encodePath`.
fn encode_segment(value: &str) -> String {
    value.replace('/', "%2F")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_normalization() {
        assert_eq!(normalize_base("http://h:1/"), "http://h:1/api/v1");
        assert_eq!(normalize_base("http://h:1/api/v1"), "http://h:1/api/v1");
        assert_eq!(normalize_base("http://h:1/api/v1/"), "http://h:1/api/v1");
    }

    #[test]
    fn assignment_extraction() {
        let v = serde_json::json!({"policy_id": "p1", "policy_version": 4});
        let a = assignment_from(Some("a1".into()), &v);
        assert_eq!(a.agent_id.as_deref(), Some("a1"));
        assert_eq!(a.policy_id.as_deref(), Some("p1"));
        assert_eq!(a.policy_version, 4);
    }
}
