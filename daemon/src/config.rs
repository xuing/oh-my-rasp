//! Daemon configuration.
//!
//! Configuration is layered, lowest precedence first:
//!   1. Built-in defaults (see the `Default` impls below).
//!   2. An optional TOML file (`--config <path>` or `./ohmyrasp-daemon.toml`).
//!   3. Environment variables (`OHMYRASP_*` / `OHMYRASP_DAEMON_*`).
//!   4. Command-line flags (highest precedence).
//!
//! Every field has a sane default so the daemon runs standalone with zero
//! configuration: it tails the agent's default spool file and serves the
//! console on `127.0.0.1:7070` with the cloud uplink disabled.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::cli::Cli;

/// Default spool file written by the Java agent's `JsonEventLogger`.
pub const DEFAULT_SPOOL: &str = "/tmp/ohmyrasp-events.jsonl";
/// Default control file polled by the Java agent's runtime.
pub const DEFAULT_CONTROL: &str = "/tmp/ohmyrasp-control.json";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub log: LogConfig,
    pub spool: SpoolConfig,
    pub control: ControlConfig,
    pub console: ConsoleConfig,
    pub cloud: CloudConfig,
    pub buffer: BufferConfig,
    pub store: StoreConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Tracing filter, e.g. `info`, `debug`, `ohmyrasp_daemon=debug`.
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SpoolConfig {
    /// NDJSON event file the agent appends to.
    pub path: PathBuf,
    /// How often to poll the spool for new bytes.
    pub poll_interval_ms: u64,
    /// When true, replay the whole existing file on startup; otherwise start
    /// at the current end-of-file so only fresh events are processed.
    pub from_start: bool,
}

impl Default for SpoolConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_SPOOL),
            poll_interval_ms: 250,
            from_start: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ControlConfig {
    /// JSON control file the daemon owns and the agent polls.
    pub path: PathBuf,
    /// Initial mode written on startup if no control file exists yet.
    /// One of `off`, `monitor`, `block`.
    pub default_mode: String,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DEFAULT_CONTROL),
            default_mode: "monitor".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleConfig {
    pub bind: SocketAddr,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:7070".parse().expect("valid default addr"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudConfig {
    /// When false the daemon runs fully offline; events stay local.
    pub enabled: bool,
    /// Base URL of the Go control plane, e.g. `http://127.0.0.1:18090`.
    pub backend_url: String,
    pub app_id: String,
    pub app_secret: String,
    pub environment_id: String,
    /// Reported host identity; defaults to the machine hostname.
    pub hostname: String,
    pub runtime: String,
    pub version: String,
    pub heartbeat_interval_s: u64,
    pub upload_interval_ms: u64,
    pub upload_batch_max: usize,
    pub request_timeout_s: u64,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend_url: String::new(),
            app_id: String::new(),
            app_secret: String::new(),
            environment_id: String::new(),
            hostname: hostname(),
            runtime: "java".into(),
            version: "unknown".into(),
            heartbeat_interval_s: 30,
            upload_interval_ms: 1000,
            upload_batch_max: 50,
            request_timeout_s: 5,
        }
    }
}

impl CloudConfig {
    /// The cloud uplink is usable only when explicitly enabled and the minimum
    /// identity fields are present (mirrors the Java `ControlPlaneConfig`).
    pub fn usable(&self) -> bool {
        self.enabled
            && !self.backend_url.trim().is_empty()
            && !self.app_id.trim().is_empty()
            && !self.app_secret.trim().is_empty()
            && !self.environment_id.trim().is_empty()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BufferConfig {
    /// Working directory for the durable offline outbox + cursor state.
    pub dir: PathBuf,
    /// Max events held in the retry buffer before the oldest are dropped.
    pub max_pending: usize,
}

impl Default for BufferConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/tmp/ohmyrasp-daemon"),
            max_pending: 10_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StoreConfig {
    /// Recent events kept in memory for the console ring buffer.
    pub capacity: usize,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self { capacity: 2000 }
    }
}

impl Config {
    /// Build the effective configuration from file + env + CLI layers.
    pub fn load(cli: &Cli) -> Result<Self> {
        let mut config = match Self::config_path(cli) {
            Some(path) => Self::from_file(&path)
                .with_context(|| format!("loading config file {}", path.display()))?,
            None => Self::default(),
        };
        config.apply_env();
        config.apply_cli(cli);
        Ok(config)
    }

    fn config_path(cli: &Cli) -> Option<PathBuf> {
        if let Some(path) = &cli.config {
            return Some(path.clone());
        }
        let default = PathBuf::from("ohmyrasp-daemon.toml");
        default.exists().then_some(default)
    }

    fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let config = toml::from_str(&text)?;
        Ok(config)
    }

    fn apply_env(&mut self) {
        if let Ok(v) = std::env::var("OHMYRASP_DAEMON_LOG") {
            self.log.level = v;
        }
        if let Ok(v) = std::env::var("OHMYRASP_DAEMON_SPOOL_PATH") {
            self.spool.path = v.into();
        }
        if let Ok(v) = std::env::var("OHMYRASP_DAEMON_CONTROL_PATH") {
            self.control.path = v.into();
        }
        if let Ok(v) = std::env::var("OHMYRASP_DAEMON_CONSOLE_BIND") {
            if let Ok(addr) = v.parse() {
                self.console.bind = addr;
            }
        }
        if let Ok(v) = std::env::var("OHMYRASP_DAEMON_CLOUD_ENABLED") {
            self.cloud.enabled = matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }
        if let Ok(v) = std::env::var("OHMYRASP_BACKEND_URL") {
            self.cloud.backend_url = v;
        }
        if let Ok(v) = std::env::var("OHMYRASP_APP_ID") {
            self.cloud.app_id = v;
        }
        if let Ok(v) = std::env::var("OHMYRASP_APP_SECRET") {
            self.cloud.app_secret = v;
        }
        if let Ok(v) = std::env::var("OHMYRASP_ENVIRONMENT_ID") {
            self.cloud.environment_id = v;
        }
        if let Ok(v) = std::env::var("OHMYRASP_HOSTNAME") {
            self.cloud.hostname = v;
        }
        if let Ok(v) = std::env::var("OHMYRASP_VERSION") {
            self.cloud.version = v;
        }
    }

    fn apply_cli(&mut self, cli: &Cli) {
        if let Some(v) = &cli.spool {
            self.spool.path = v.clone();
        }
        if let Some(v) = &cli.control {
            self.control.path = v.clone();
        }
        if let Some(v) = cli.console_bind {
            self.console.bind = v;
        }
        if let Some(v) = &cli.backend_url {
            self.cloud.backend_url = v.clone();
            self.cloud.enabled = true;
        }
        if cli.cloud {
            self.cloud.enabled = true;
        }
        if cli.from_start {
            self.spool.from_start = true;
        }
    }
}

/// Best-effort machine hostname; falls back to `"unknown"`.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
        })
        .unwrap_or_else(|| "unknown".into())
}
