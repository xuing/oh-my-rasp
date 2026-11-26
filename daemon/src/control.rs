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
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::util::now_rfc3339;

/// The largest control document, in bytes, that the agents read: both agent engines ignore a
/// control file larger than this, which would also stop a mode change from reaching them. The
/// daemon refuses to write a larger document and keeps the previous one. This is one contract
/// value: `java-agent/contracts/agent-daemon/control/limits.properties` holds it, and the tests
/// of the daemon and of both agent engines compare their own constant with that file.
pub const MAX_CONTROL_BYTES: usize = 1 << 20;

/// The control document the daemon was asked to write is larger than the agents read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlTooLarge {
    pub size_bytes: usize,
    pub limit_bytes: usize,
}

impl fmt::Display for ControlTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the control document would be {} bytes, more than the {} bytes the agents read",
            self.size_bytes, self.limit_bytes
        )
    }
}

impl std::error::Error for ControlTooLarge {}

/// The write the daemon last refused, for the status views. Cleared by the next write that
/// succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WriteRefused {
    /// What was being written: `policy` (a cloud policy), `update` (a console change) or
    /// `existing` (the file found at start-up).
    pub change: &'static str,
    pub size_bytes: usize,
    pub limit_bytes: usize,
    pub at: String,
    pub message: String,
}

/// What the daemon reports about writing the control file, next to the document itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ControlStatus {
    /// Set while the last attempt to write the control file was refused; the file still holds
    /// the previous document, and the agents are not following the change that was refused.
    pub write_refused: Option<WriteRefused>,
}

/// Detection mode. Ordered from least to most intrusive.
///
/// Written as the canonical lowercase word, read as any spelling [`Mode::parse`] accepts: an
/// operator who edits the control file by hand may write `Protect` or `record`, and the daemon
/// rewrites the canonical word the next time it writes the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Mode::parse(&text).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown mode {text:?}: expected off, monitor or block (or an alias)"
            ))
        })
    }
}

impl Mode {
    /// The spellings are exactly those both agent engines accept (`DetectionMode.parse` of the
    /// primary agent and `RaspRuntime.parseMode` of the backports, which agree): `off`,
    /// `disabled`, `none` / `monitor`, `record`, `observe`, `log` / `block`, `blocking`,
    /// `protect`, in any letter case, with characters up to U+0020 around them ignored (Java's
    /// `String.trim`, not Rust's wider whitespace). The contract examples in
    /// `control/hand-edited/` pin them.
    pub fn parse(value: &str) -> Option<Self> {
        match value
            .trim_matches(|c: char| c <= ' ')
            .to_lowercase()
            .as_str()
        {
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
    /// Cloud-assigned policy document, passed through verbatim for the agent to
    /// parse and install. The daemon owns the cloud handshake; the agent only
    /// ever sees the policy via this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
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
            policy: None,
            revision: 1,
            updated_at: now_rfc3339(),
        }
    }
}

/// Thread-safe controller wrapping the control state and its backing file.
pub struct Controller {
    path: PathBuf,
    state: Mutex<ControlState>,
    status: Mutex<ControlStatus>,
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
        let controller = Self {
            path: path.to_path_buf(),
            state: Mutex::new(state.clone()),
            status: Mutex::new(ControlStatus::default()),
        };
        // A file left larger than the agents read (edited by hand) is kept as it is, and
        // reported; refusing to start over it would take the console down with it.
        match controller.write(&state, "existing") {
            Ok(()) => {}
            Err(err) if err.downcast_ref::<ControlTooLarge>().is_some() => {}
            Err(err) => return Err(err),
        }
        Ok(controller)
    }

    pub fn snapshot(&self) -> ControlState {
        self.state.lock().expect("control mutex").clone()
    }

    /// What the daemon reports about writing the control file; see [`ControlStatus`].
    pub fn status(&self) -> ControlStatus {
        self.status.lock().expect("control status mutex").clone()
    }

    /// Apply a partial update from the console. Any field left `None` is kept. When the
    /// resulting document would be larger than the agents read, nothing changes and the error is
    /// a [`ControlTooLarge`].
    pub fn update(
        &self,
        mode: Option<Mode>,
        algorithms: Option<BTreeMap<String, bool>>,
    ) -> Result<ControlState> {
        let mut guard = self.state.lock().expect("control mutex");
        let mut next = guard.clone();
        if let Some(mode) = mode {
            next.mode = mode;
        }
        if let Some(updates) = algorithms {
            for (name, enabled) in updates {
                next.algorithms.insert(name, enabled);
            }
        }
        next.revision += 1;
        next.updated_at = now_rfc3339();
        self.write(&next, "update")?;
        *guard = next.clone();
        Ok(next)
    }

    /// Install a cloud-assigned policy document, preserving mode/algorithm
    /// settings. Idempotent: a no-op (no revision bump, no write) when the
    /// policy is unchanged, so repeated heartbeat pulls don't churn the file.
    /// A policy that would make the document larger than the agents read is refused: the
    /// previous document stays in place and the error is a [`ControlTooLarge`].
    pub fn set_policy(&self, policy: Option<String>) -> Result<bool> {
        let mut guard = self.state.lock().expect("control mutex");
        if guard.policy == policy {
            return Ok(false);
        }
        let mut next = guard.clone();
        next.policy = policy;
        next.revision += 1;
        next.updated_at = now_rfc3339();
        self.write(&next, "policy")?;
        *guard = next;
        Ok(true)
    }

    /// Write `state` as the control file, unless it is larger than the agents read. On a refusal
    /// the file is untouched, the refusal is logged and kept for [`Controller::status`], and the
    /// error is a [`ControlTooLarge`].
    fn write(&self, state: &ControlState, change: &'static str) -> Result<()> {
        let json = serde_json::to_string_pretty(state)?;
        if json.len() > MAX_CONTROL_BYTES {
            return Err(self.refuse(change, json.len()).into());
        }
        self.persist(&json)?;
        let previous = self
            .status
            .lock()
            .expect("control status mutex")
            .write_refused
            .take();
        if previous.is_some() {
            tracing::info!("control file written again; the refused change no longer applies");
        }
        Ok(())
    }

    fn refuse(&self, change: &'static str, size_bytes: usize) -> ControlTooLarge {
        let refusal = ControlTooLarge {
            size_bytes,
            limit_bytes: MAX_CONTROL_BYTES,
        };
        let mut status = self.status.lock().expect("control status mutex");
        // The cloud policy is pulled again at every heartbeat: say it loudly once, not each time.
        let repeated = status
            .write_refused
            .as_ref()
            .is_some_and(|r| r.change == change && r.size_bytes == size_bytes);
        if repeated {
            tracing::debug!(change, size_bytes, "control file write still refused");
        } else {
            tracing::error!(
                change,
                size_bytes,
                limit_bytes = MAX_CONTROL_BYTES,
                path = %self.path.display(),
                "refusing to write the control file: the document would be larger than the agents \
                 read, which ignore such a file; keeping the previous document"
            );
            status.write_refused = Some(WriteRefused {
                change,
                size_bytes,
                limit_bytes: MAX_CONTROL_BYTES,
                at: now_rfc3339(),
                message: refusal.to_string(),
            });
        }
        refusal
    }

    /// Atomically write the control file (temp file + rename) so the agent
    /// never observes a half-written document.
    fn persist(&self, json: &str) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).ok();
        }
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes())
            .with_context(|| format!("writing control temp {}", tmp.display()))?;
        // The control file carries the cloud policy; keep it owner-only. Set the
        // mode on the temp file before the rename so the file is never exposed
        // world-readable, even briefly, under its final name.
        crate::util::restrict_to_owner(&tmp)
            .with_context(|| format!("restricting control temp {}", tmp.display()))?;
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

    #[test]
    fn policy_passthrough_is_preserved_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();

        assert!(ctrl.set_policy(Some("{\"version\":4}".into())).unwrap());
        assert!(
            !ctrl.set_policy(Some("{\"version\":4}".into())).unwrap(),
            "unchanged → no-op"
        );
        let rev = ctrl.snapshot().revision;

        // A console mode change must keep the policy intact.
        ctrl.update(Some(Mode::Block), None).unwrap();
        let snap = ctrl.snapshot();
        assert_eq!(snap.policy.as_deref(), Some("{\"version\":4}"));
        assert_eq!(snap.mode, Mode::Block);
        assert!(snap.revision > rev);

        // Persisted file round-trips the policy.
        let reloaded = Controller::load_or_init(&path, Mode::Off).unwrap();
        assert_eq!(
            reloaded.snapshot().policy.as_deref(),
            Some("{\"version\":4}")
        );
    }

    #[cfg(unix)]
    #[test]
    fn control_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        // Freshly written on load.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        // Still owner-only after a subsequent rewrite via the temp+rename path.
        ctrl.update(Some(Mode::Block), None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    /// A document whose serialized form is exactly `bytes` long. The policy text is plain, so
    /// each byte of it is one byte of the file.
    fn state_of_size(bytes: usize) -> ControlState {
        let mut state = ControlState {
            mode: Mode::Monitor,
            algorithms: BTreeMap::new(),
            policy: Some(String::new()),
            revision: 2,
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let empty = serde_json::to_string_pretty(&state).unwrap().len();
        state.policy = Some("a".repeat(bytes - empty));
        assert_eq!(serde_json::to_string_pretty(&state).unwrap().len(), bytes);
        state
    }

    #[test]
    fn the_document_may_be_exactly_the_limit_and_not_a_byte_more() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();

        ctrl.write(&state_of_size(MAX_CONTROL_BYTES), "policy")
            .expect("a document of exactly the limit is written");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len() as usize,
            MAX_CONTROL_BYTES
        );
        let file = std::fs::read(&path).unwrap();

        let err = ctrl
            .write(&state_of_size(MAX_CONTROL_BYTES + 1), "policy")
            .unwrap_err();
        let refusal = err
            .downcast_ref::<ControlTooLarge>()
            .expect("a ControlTooLarge");
        assert_eq!(refusal.size_bytes, MAX_CONTROL_BYTES + 1);
        assert_eq!(refusal.limit_bytes, MAX_CONTROL_BYTES);
        assert_eq!(std::fs::read(&path).unwrap(), file, "the file is untouched");
    }

    #[test]
    fn a_policy_that_makes_the_document_too_large_is_refused_and_the_previous_document_stays() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        assert!(ctrl.set_policy(Some("{\"version\":1}".into())).unwrap());
        let file = std::fs::read(&path).unwrap();
        let before = ctrl.snapshot();
        assert!(ctrl.status().write_refused.is_none());

        let err = ctrl
            .set_policy(Some("a".repeat(MAX_CONTROL_BYTES)))
            .unwrap_err();
        let refusal = err
            .downcast_ref::<ControlTooLarge>()
            .expect("a ControlTooLarge");
        assert!(refusal.size_bytes > MAX_CONTROL_BYTES);
        assert_eq!(refusal.limit_bytes, MAX_CONTROL_BYTES);
        assert!(
            err.to_string().contains(&refusal.size_bytes.to_string())
                && err.to_string().contains("1048576"),
            "the error names the size and the limit: {err}"
        );
        // Nothing changed: the file, the state in memory and the revision.
        assert_eq!(std::fs::read(&path).unwrap(), file);
        let after = ctrl.snapshot();
        assert_eq!(after.policy, before.policy);
        assert_eq!(after.revision, before.revision);
        let status = ctrl
            .status()
            .write_refused
            .expect("the refusal is reported");
        assert_eq!(
            (status.change, status.size_bytes, status.limit_bytes),
            ("policy", refusal.size_bytes, MAX_CONTROL_BYTES)
        );

        // A write that succeeds clears the report.
        assert!(ctrl.set_policy(Some("{\"version\":2}".into())).unwrap());
        assert!(ctrl.status().write_refused.is_none());
    }

    #[test]
    fn a_console_update_that_would_make_the_document_too_large_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        // A policy that fits (with room for any timestamp), leaving no room for a long switch name.
        let policy = state_of_size(MAX_CONTROL_BYTES - 100).policy;
        assert!(ctrl.set_policy(policy).unwrap());
        let file = std::fs::read(&path).unwrap();
        let revision = ctrl.snapshot().revision;

        let mut toggles = BTreeMap::new();
        toggles.insert("s".repeat(300), false);
        let err = ctrl.update(Some(Mode::Block), Some(toggles)).unwrap_err();
        assert!(err.downcast_ref::<ControlTooLarge>().is_some(), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), file);
        assert_eq!(ctrl.snapshot().mode, Mode::Monitor);
        assert!(ctrl.snapshot().algorithms.is_empty());
        assert_eq!(ctrl.snapshot().revision, revision);
        assert_eq!(ctrl.status().write_refused.unwrap().change, "update");
    }

    #[test]
    fn a_file_found_larger_than_the_agents_read_is_kept_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let big = format!(
            "{{\"mode\":\"block\",\"policy\":\"{}\",\"revision\":4}}",
            "a".repeat(MAX_CONTROL_BYTES)
        );
        std::fs::write(&path, &big).unwrap();

        let ctrl = Controller::load_or_init(&path, Mode::Monitor).expect("the daemon still starts");

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            big,
            "the file is not rewritten"
        );
        assert_eq!(ctrl.snapshot().mode, Mode::Block);
        assert_eq!(ctrl.status().write_refused.unwrap().change, "existing");
    }

    #[test]
    fn every_spelling_the_agents_accept_parses_in_any_case() {
        let spellings = [
            ("off", Mode::Off),
            ("disabled", Mode::Off),
            ("none", Mode::Off),
            ("monitor", Mode::Monitor),
            ("record", Mode::Monitor),
            ("observe", Mode::Monitor),
            ("log", Mode::Monitor),
            ("block", Mode::Block),
            ("blocking", Mode::Block),
            ("protect", Mode::Block),
        ];
        for (word, mode) in spellings {
            for text in [
                word.to_string(),
                word.to_uppercase(),
                format!("{}{}", word[..1].to_uppercase(), &word[1..]),
                format!(" {word}\t"),
            ] {
                assert_eq!(Mode::parse(&text), Some(mode), "{text:?}");
            }
        }
        // Like Java's trim and toLowerCase(Locale.ROOT): control characters around the word are
        // ignored, a no-break space is not, and the Kelvin sign is a letter `k`.
        assert_eq!(Mode::parse("\u{1}block\u{1f}"), Some(Mode::Block));
        assert_eq!(Mode::parse("\u{a0}block"), None);
        assert_eq!(Mode::parse("BLOC\u{212a}"), Some(Mode::Block));
        for text in ["", "nonsense", "blocked", "on", "mon itor"] {
            assert_eq!(Mode::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn a_hand_edited_mode_is_kept_and_written_back_as_the_canonical_word() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        std::fs::write(
            &path,
            r#"{"mode":" Protect ","algorithms":{"sqli":false},"revision":7,"updated_at":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();

        let ctrl = Controller::load_or_init(&path, Mode::Off).unwrap();

        let state = ctrl.snapshot();
        assert_eq!(state.mode, Mode::Block, "not reinitialised to the default");
        assert_eq!(state.revision, 7);
        assert_eq!(state.algorithms.get("sqli"), Some(&false));
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["mode"], "block");
        assert_eq!(written["revision"], 7);
    }

    #[test]
    fn a_mode_nobody_accepts_still_reinitialises_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        std::fs::write(&path, r#"{"mode":"nonsense","revision":7}"#).unwrap();
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        assert_eq!(ctrl.snapshot().mode, Mode::Monitor);
        assert_eq!(ctrl.snapshot().revision, 1);
    }
}
