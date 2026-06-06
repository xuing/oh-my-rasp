//! Agent control state.
//!
//! The daemon is the single owner of the **control file** that the Java agent
//! polls. This module holds the in-memory control state, persists it
//! atomically to disk, and exposes mutation helpers used by the console.
//!
//! Control flows one way: console/operator → daemon → control file → agent.
//! The same file is the standalone control surface, so an operator can edit it
//! by hand when no daemon console is running.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::util::now_rfc3339;

/// Detection mode. Ordered from least to most intrusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Detection disabled entirely — the agent should short-circuit hooks for
    /// the lowest possible business overhead.
    Off,
    /// Detect and record, but never block (a.k.a. "record"/"observe").
    Monitor,
    /// Detect, record, and block active-request attacks.
    Block,
}

impl Mode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "disabled" | "none" => Some(Self::Off),
            "monitor" | "record" | "observe" | "log" => Some(Self::Monitor),
            "block" | "blocking" | "protect" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Monitor => "monitor",
            Self::Block => "block",
        }
    }
}

/// Serializable control document — exactly what is written to the control file
/// and what the agent parses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlState {
    pub mode: Mode,
    /// Per-algorithm enable flags. An algorithm absent from this map is treated
    /// as enabled by the agent; a present `false` disables it.
    #[serde(default)]
    pub algorithms: BTreeMap<String, bool>,
    /// Monotonic revision; bumped on every change so the agent can cheaply
    /// detect updates.
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub updated_at: String,
}

impl ControlState {
    fn initial(mode: Mode) -> Self {
        Self {
            mode,
            algorithms: BTreeMap::new(),
            revision: 1,
            updated_at: now_rfc3339(),
        }
    }
}

/// Thread-safe controller wrapping the control state and its backing file.
pub struct Controller {
    path: PathBuf,
    state: Mutex<ControlState>,
}

impl Controller {
    /// Load an existing control file or initialise one with `default_mode`,
    /// writing it to disk so the agent immediately has a known state.
    pub fn load_or_init(path: &Path, default_mode: Mode) -> Result<Self> {
        let state = match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str::<ControlState>(&text)
                .with_context(|| format!("parsing control file {}", path.display()))
                .unwrap_or_else(|err| {
                    tracing::warn!(%err, "control file unreadable; reinitialising");
                    ControlState::initial(default_mode)
                }),
            Err(_) => ControlState::initial(default_mode),
        };
        let controller = Self { path: path.to_path_buf(), state: Mutex::new(state) };
        controller.persist()?;
        Ok(controller)
    }

    pub fn snapshot(&self) -> ControlState {
        self.state.lock().expect("control mutex").clone()
    }

    /// Apply a partial update from the console. Any field left `None` is kept.
    pub fn update(&self, mode: Option<Mode>, algorithms: Option<BTreeMap<String, bool>>) -> Result<ControlState> {
        {
            let mut guard = self.state.lock().expect("control mutex");
            if let Some(mode) = mode {
                guard.mode = mode;
            }
            if let Some(updates) = algorithms {
                for (name, enabled) in updates {
                    guard.algorithms.insert(name, enabled);
                }
            }
            guard.revision += 1;
            guard.updated_at = now_rfc3339();
        }
        self.persist()?;
        Ok(self.snapshot())
    }

    /// Atomically write the control file (temp file + rename) so the agent
    /// never observes a half-written document.
    fn persist(&self) -> Result<()> {
        let state = self.snapshot();
        let json = serde_json::to_string_pretty(&state)?;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes())
            .with_context(|| format!("writing control temp {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming control file into place {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_round_trips() {
        for m in [Mode::Off, Mode::Monitor, Mode::Block] {
            assert_eq!(Mode::parse(m.as_str()), Some(m));
        }
        assert_eq!(Mode::parse("RECORD"), Some(Mode::Monitor));
        assert_eq!(Mode::parse("nonsense"), None);
    }

    #[test]
    fn persists_and_bumps_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        assert!(path.exists());
        let before = ctrl.snapshot();
        assert_eq!(before.mode, Mode::Monitor);

        let mut toggles = BTreeMap::new();
        toggles.insert("sqli".to_string(), false);
        let after = ctrl.update(Some(Mode::Block), Some(toggles)).unwrap();
        assert_eq!(after.mode, Mode::Block);
        assert_eq!(after.algorithms.get("sqli"), Some(&false));
        assert_eq!(after.revision, before.revision + 1);

        // A fresh controller reads the persisted file back.
        let reloaded = Controller::load_or_init(&path, Mode::Off).unwrap();
        assert_eq!(reloaded.snapshot().mode, Mode::Block);
    }
}
