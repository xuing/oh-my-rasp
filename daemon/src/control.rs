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
use std::hash::{DefaultHasher, Hash, Hasher};
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
    /// Whether the agents are applying the document the daemon holds in memory. True for a
    /// refused change: the file still holds that document and the agents read it. False for an
    /// `existing` file found larger than the agents read: they ignore it, so they apply neither
    /// it nor the daemon's in-memory state, and keep the mode they had.
    pub agents_apply_state: bool,
    /// What the refusal is about, so that the same one is logged once: the policy assignment
    /// (its id and version, else a hash of its text). `None` for a change that has no repeat.
    #[serde(skip)]
    pub identity: Option<String>,
}

/// A control file found at start-up that was larger than the agents read, which the daemon
/// rewrote smaller. The agents had been ignoring it; they apply it from this write on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OversizedFileReplaced {
    pub found_bytes: usize,
    pub written_bytes: usize,
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
    /// Set when the control file found at start-up was larger than the agents read and the
    /// daemon wrote it again within the limit.
    pub oversized_file_replaced: Option<OversizedFileReplaced>,
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

/// Whether an agent blocks a context-dependent finding made with no request evidence (a
/// scheduled job, a message consumer, start-up code), on every agent line. Inside a request
/// nothing changes, and findings whose argument is the exploit itself block whatever it says.
///
/// Two parties set it, and the agents need both to allow blocking, as a hardening finding needs
/// both the top-level `mode` and the policy's `hardening.mode`:
///
/// - the host: the control document's top-level `outside_request` member, which only the host
///   console (`POST /api/control`) or an operator's hand edit writes. Absent or null means the
///   agent's start-up value. The daemon keeps it as found: a value nobody accepts stays in the
///   file (the agents ignore it and keep what they had) and is reported, never rewritten.
/// - the cloud: `config.hardening.outside_request` inside the policy the cloud assigns. It
///   travels with the policy: a policy without it, or no policy, does not restrict.
///
/// Read as `block` or `log` in any letter case with characters up to U+0020 around the word
/// ignored, as both agent engines read it (`OutsideRequest.parse`), and written as the lowercase
/// word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutsideRequest {
    /// Block outside a request as inside one (the default).
    Block,
    /// Record the finding with the action `log` and let the operation run.
    Log,
}

impl OutsideRequest {
    pub fn parse(value: &str) -> Option<Self> {
        match value
            .trim_matches(|c: char| c <= ' ')
            .to_lowercase()
            .as_str()
        {
            "block" => Some(Self::Block),
            "log" => Some(Self::Log),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Log => "log",
        }
    }

    /// The setting a cloud policy carries, in `config.hardening.outside_request` (the
    /// per-application `protection.hardening` setting of the control plane), if it carries one
    /// the agents accept.
    pub fn of_policy(policy: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(policy).ok()?;
        Self::parse(
            value
                .get("config")?
                .get("hardening")?
                .get("outside_request")?
                .as_str()?,
        )
    }
}

/// The host's `outside_request` member as the control document holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOutsideRequest {
    /// Absent (or null): the agents use their start-up value.
    Unset,
    /// A word the agents accept.
    Set(OutsideRequest),
    /// A value nobody accepts, kept as found: the agents ignore it and keep what they had.
    Invalid,
}

/// The `outside_request` the agents apply, with where it comes from, for the consoles: the
/// host's member, the cloud policy's value, and what follows from the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutsideRequestView {
    /// The host's setting: `block`, `log`, `invalid`, or null when it has none.
    pub host: Option<&'static str>,
    /// The cloud policy's `config.hardening.outside_request`: `block`, `log`, or null.
    pub cloud: Option<&'static str>,
    /// What the agents apply: `block`, `log`, `start-up` (each agent's start-up value, block
    /// unless it was started with log) or `unchanged` (the agents keep the value they had).
    pub effective: &'static str,
    /// Who decides `effective`: `cloud`, `host`, `agent` or `invalid`.
    pub source: &'static str,
}

/// Serializable control document — exactly what is written to the control file
/// and what the agent parses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlState {
    pub mode: Mode,
    /// The host's `outside_request` exactly as the document holds it: absent unless the host set
    /// it; a value nobody accepts is kept as found. See [`OutsideRequest`] and
    /// [`ControlState::host_outside_request`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outside_request: Option<serde_json::Value>,
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
            outside_request: None,
            algorithms: BTreeMap::new(),
            policy: None,
            revision: 1,
            updated_at: now_rfc3339(),
        }
    }

    /// The host's `outside_request`, as the agents read the member.
    pub fn host_outside_request(&self) -> HostOutsideRequest {
        match &self.outside_request {
            None | Some(serde_json::Value::Null) => HostOutsideRequest::Unset,
            Some(serde_json::Value::String(text)) => OutsideRequest::parse(text)
                .map_or(HostOutsideRequest::Invalid, HostOutsideRequest::Set),
            Some(_) => HostOutsideRequest::Invalid,
        }
    }

    /// The cloud policy's `config.hardening.outside_request`, when it carries one the agents
    /// accept.
    pub fn cloud_outside_request(&self) -> Option<OutsideRequest> {
        self.policy.as_deref().and_then(OutsideRequest::of_policy)
    }

    /// What the agents apply to a context-dependent finding with no request evidence, and why:
    /// a cloud `log` decides whatever the host says; otherwise the host's word, else each
    /// agent's start-up value.
    pub fn outside_request_view(&self) -> OutsideRequestView {
        let host = self.host_outside_request();
        let cloud = self.cloud_outside_request();
        let (effective, source) = if cloud == Some(OutsideRequest::Log) {
            ("log", "cloud")
        } else {
            match host {
                HostOutsideRequest::Set(value) => (value.as_str(), "host"),
                HostOutsideRequest::Unset => ("start-up", "agent"),
                HostOutsideRequest::Invalid => ("unchanged", "invalid"),
            }
        };
        OutsideRequestView {
            host: match host {
                HostOutsideRequest::Unset => None,
                HostOutsideRequest::Set(value) => Some(value.as_str()),
                HostOutsideRequest::Invalid => Some("invalid"),
            },
            cloud: cloud.map(OutsideRequest::as_str),
            effective,
            source,
        }
    }
}

/// What a refused policy is called in the log and the status: the assignment the cloud reports,
/// else a hash of the policy text (a size would change with the width of the timestamp).
fn policy_identity(text: &str, assignment: Option<&str>) -> String {
    match assignment {
        Some(assigned) => assigned.to_string(),
        None => {
            let mut hasher = DefaultHasher::new();
            text.hash(&mut hasher);
            format!("sha:{:016x}", hasher.finish())
        }
    }
}

/// The control document in `text`, as the agents read it: a member named twice counts with its
/// last value (serde's struct reader would refuse the document and the daemon would reinitialise
/// it), and the host's `outside_request` is rewritten as its canonical word when the agents
/// accept it and kept as found when they do not.
fn parse_document(text: &str) -> Result<ControlState> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let mut state: ControlState = serde_json::from_value(value)?;
    match state.host_outside_request() {
        HostOutsideRequest::Unset => state.outside_request = None,
        HostOutsideRequest::Set(word) => {
            state.outside_request = Some(serde_json::Value::from(word.as_str()));
        }
        HostOutsideRequest::Invalid => {
            tracing::warn!(
                value = %state.outside_request.as_ref().map_or_else(String::new, ToString::to_string),
                "outside_request in the control file is neither block nor log; kept as found: the \
                 agents ignore it and keep the value they had"
            );
        }
    }
    Ok(state)
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
        // The size of the file as found: the agents measure that, not the document the daemon
        // would write from it.
        let mut found_bytes = None;
        let state = match std::fs::read_to_string(path) {
            Ok(text) => parse_document(&text)
                .with_context(|| format!("parsing control file {}", path.display()))
                .inspect(|_| found_bytes = Some(text.len()))
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
        // A file left larger than the agents read (edited by hand) is kept as it is when the
        // document does not fit either, and reported; refusing to start over it would take the
        // console down with it.
        match controller.write_existing(&state, found_bytes) {
            Ok(()) => {}
            Err(err) if err.downcast_ref::<ControlTooLarge>().is_some() => {}
            Err(err) => return Err(err),
        }
        Ok(controller)
    }

    pub fn snapshot(&self) -> ControlState {
        self.state.lock().expect("control mutex").clone()
    }

    /// The document and the status of the last write, as one snapshot. Writers hold the state
    /// lock while they record a refusal or its clearing, so reading both under it never shows a
    /// document from one write beside the refusal of another.
    pub fn view(&self) -> (ControlState, ControlStatus) {
        let state = self.state.lock().expect("control mutex");
        let status = self.status.lock().expect("control status mutex").clone();
        (state.clone(), status)
    }

    /// What the daemon reports about writing the control file; see [`ControlStatus`].
    pub fn status(&self) -> ControlStatus {
        self.status.lock().expect("control status mutex").clone()
    }

    /// Apply a partial update from the console. Any field left `None` is kept. When the
    /// resulting document would be larger than the agents read, nothing changes and the error is
    /// a [`ControlTooLarge`].
    #[cfg(test)]
    pub fn update(
        &self,
        mode: Option<Mode>,
        algorithms: Option<BTreeMap<String, bool>>,
    ) -> Result<ControlState> {
        self.update_with(mode, None, algorithms)
    }

    /// Apply a partial update from the console: the mode, the host's `outside_request` and
    /// per-algorithm switches. Any field left `None` is kept; `outside_request` of `Some(None)`
    /// removes the host's member, so the agents return to the cloud's value or their start-up
    /// value. When the resulting document would be larger than the agents read, nothing changes
    /// and the error is a [`ControlTooLarge`].
    pub fn update_with(
        &self,
        mode: Option<Mode>,
        outside_request: Option<Option<OutsideRequest>>,
        algorithms: Option<BTreeMap<String, bool>>,
    ) -> Result<ControlState> {
        let mut guard = self.state.lock().expect("control mutex");
        let mut next = guard.clone();
        if let Some(mode) = mode {
            next.mode = mode;
        }
        if let Some(outside_request) = outside_request {
            next.outside_request =
                outside_request.map(|value| serde_json::Value::from(value.as_str()));
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
    #[cfg(test)]
    pub fn set_policy(&self, policy: Option<String>) -> Result<bool> {
        self.set_policy_assigned(policy, None)
    }

    /// [`Controller::set_policy`] for a policy the cloud assigned under `assignment` (its id and
    /// version, as the cloud reports them). A refusal is identified by that assignment, else by a
    /// hash of the policy text, and logged once: the same assignment pulled again at the next
    /// heartbeat is not logged again, even when the document comes out a byte longer or shorter.
    ///
    /// When the policy asked for is the one installed, the refusal of an earlier policy no
    /// longer applies and is cleared.
    ///
    /// The cloud's `outside_request` stays inside the policy (`config.hardening`), where the
    /// agents read it: installing, replacing or withdrawing a policy changes it with the policy
    /// and never touches the host's top-level member.
    pub fn set_policy_assigned(
        &self,
        policy: Option<String>,
        assignment: Option<&str>,
    ) -> Result<bool> {
        let mut guard = self.state.lock().expect("control mutex");
        if guard.policy == policy {
            self.clear_policy_refusal();
            return Ok(false);
        }
        let identity = policy
            .as_deref()
            .map(|text| policy_identity(text, assignment));
        let mut next = guard.clone();
        next.policy = policy;
        next.revision += 1;
        next.updated_at = now_rfc3339();
        self.write_identified(&next, "policy", identity)?;
        *guard = next;
        Ok(true)
    }

    /// Whether the last refusal was a policy the cloud assigned.
    #[cfg(test)]
    pub fn policy_refused(&self) -> bool {
        self.status
            .lock()
            .expect("control status mutex")
            .write_refused
            .as_ref()
            .is_some_and(|r| r.change == "policy")
    }

    /// The refusal of a policy is over once the policy the cloud wants is the installed one.
    fn clear_policy_refusal(&self) {
        let mut status = self.status.lock().expect("control status mutex");
        if status
            .write_refused
            .as_ref()
            .is_some_and(|r| r.change == "policy")
        {
            status.write_refused = None;
            tracing::info!(
                "the cloud no longer assigns the policy that was refused; the control file holds \
                 the policy it wants"
            );
        }
    }

    /// Write `state` as the control file, unless it is larger than the agents read. On a refusal
    /// the file is untouched, the refusal is logged and kept for [`Controller::status`], and the
    /// error is a [`ControlTooLarge`].
    fn write(&self, state: &ControlState, change: &'static str) -> Result<()> {
        self.write_identified(state, change, None)
    }

    /// [`Controller::write`], where `identity` names what is refused (a policy assignment), so
    /// that a refusal that comes back at every heartbeat is logged once.
    fn write_identified(
        &self,
        state: &ControlState,
        change: &'static str,
        identity: Option<String>,
    ) -> Result<()> {
        let json = serde_json::to_string_pretty(state)?;
        if json.len() > MAX_CONTROL_BYTES {
            return Err(self.refuse(change, json.len(), None, identity).into());
        }
        self.persist(&json)?;
        self.clear_refusal();
        Ok(())
    }

    /// The write of the document found at start-up. `found_bytes` is the size of the file as it
    /// lay on disk (`None` when there was none, or it could not be read as a document).
    ///
    /// A file larger than the limit as found is one the agents were ignoring. When the document
    /// fits once the daemon writes it, it is written, and the log and the status say that the
    /// agents apply it from now on. When it does not fit, the file is kept, and the refusal
    /// says that the agents are not applying the daemon's in-memory state.
    fn write_existing(&self, state: &ControlState, found_bytes: Option<usize>) -> Result<()> {
        let found_oversized = found_bytes.filter(|bytes| *bytes > MAX_CONTROL_BYTES);
        let json = serde_json::to_string_pretty(state)?;
        if json.len() > MAX_CONTROL_BYTES {
            let message = found_oversized.map(|found| {
                format!(
                    "the control file found at start-up is {found} bytes (the daemon's document \
                     would be {} bytes), more than the {MAX_CONTROL_BYTES} bytes the agents read: \
                     they ignore the file, keep the mode they had, and are not applying the \
                     daemon's in-memory state",
                    json.len()
                )
            });
            return Err(self.refuse("existing", json.len(), message, None).into());
        }
        self.persist(&json)?;
        self.clear_refusal();
        if let Some(found) = found_oversized {
            let message = format!(
                "the control file found at start-up was {found} bytes, more than the \
                 {MAX_CONTROL_BYTES} bytes the agents read, so they had been ignoring it; the \
                 daemon wrote it again as {} bytes and the agents will now apply it",
                json.len()
            );
            tracing::warn!(
                found_bytes = found,
                written_bytes = json.len(),
                limit_bytes = MAX_CONTROL_BYTES,
                path = %self.path.display(),
                "{message}"
            );
            self.status
                .lock()
                .expect("control status mutex")
                .oversized_file_replaced = Some(OversizedFileReplaced {
                found_bytes: found,
                written_bytes: json.len(),
                limit_bytes: MAX_CONTROL_BYTES,
                at: now_rfc3339(),
                message,
            });
        }
        Ok(())
    }

    fn clear_refusal(&self) {
        let previous = self
            .status
            .lock()
            .expect("control status mutex")
            .write_refused
            .take();
        if previous.is_some() {
            tracing::info!("control file written again; the refused change no longer applies");
        }
    }

    fn refuse(
        &self,
        change: &'static str,
        size_bytes: usize,
        message: Option<String>,
        identity: Option<String>,
    ) -> ControlTooLarge {
        let refusal = ControlTooLarge {
            size_bytes,
            limit_bytes: MAX_CONTROL_BYTES,
        };
        // Whether the agents apply the daemon's state depends on the file as it lies on disk
        // after this attempt, not on which kind of write was refused: a file the agents ignore
        // stays ignored however many later changes are refused too.
        let on_disk = std::fs::metadata(&self.path).map_or(0, |meta| meta.len() as usize);
        let agents_apply_state = on_disk <= MAX_CONTROL_BYTES;
        let message = message.unwrap_or_else(|| {
            if agents_apply_state {
                refusal.to_string()
            } else {
                format!(
                    "{refusal}; the control file on disk is {on_disk} bytes, more than the \
                     {MAX_CONTROL_BYTES} bytes the agents read: they ignore it, keep the mode \
                     they had, and are not applying the daemon's in-memory state"
                )
            }
        });
        let mut status = self.status.lock().expect("control status mutex");
        // The cloud policy is pulled again at every heartbeat: say it loudly once per
        // assignment, not each time, and not again because the same text came out a byte longer.
        let repeated = identity.is_some()
            && status
                .write_refused
                .as_ref()
                .is_some_and(|r| r.change == change && r.identity == identity);
        if repeated {
            if let Some(refused) = status.write_refused.as_mut() {
                refused.agents_apply_state = agents_apply_state;
            }
            tracing::debug!(change, size_bytes, "control file write still refused");
        } else {
            tracing::error!(
                change,
                size_bytes,
                limit_bytes = MAX_CONTROL_BYTES,
                agents_apply_state,
                path = %self.path.display(),
                "refusing to write the control file: {message}"
            );
            status.write_refused = Some(WriteRefused {
                change,
                size_bytes,
                limit_bytes: MAX_CONTROL_BYTES,
                at: now_rfc3339(),
                message,
                agents_apply_state,
                identity,
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
            outside_request: None,
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

    /// A hand-edited file padded with blanks is over the limit as found, though the document is
    /// small: the agents were ignoring it (a mode change in it included). The daemon writes it
    /// again, and says in the log and the status that the agents apply it from now on.
    #[test]
    fn a_file_over_the_limit_as_found_that_fits_once_written_is_rewritten_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let padded = format!(
            "{{\"mode\":\"off\",\"revision\":4}}{}",
            " ".repeat(MAX_CONTROL_BYTES)
        );
        std::fs::write(&path, &padded).unwrap();

        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.len() < 1000, "rewritten small: {}", written.len());
        assert_eq!(ctrl.snapshot().mode, Mode::Off);
        let status = ctrl.status();
        assert!(status.write_refused.is_none(), "{status:?}");
        let replaced = status.oversized_file_replaced.expect("the status says so");
        assert_eq!(replaced.found_bytes, padded.len());
        assert_eq!(replaced.written_bytes, written.len());
        assert_eq!(replaced.limit_bytes, MAX_CONTROL_BYTES);
        assert!(
            replaced.message.contains(&padded.len().to_string())
                && replaced.message.contains("1048576")
                && replaced.message.contains("will now apply it"),
            "{}",
            replaced.message
        );
        // A file of exactly the limit is one the agents read: nothing to report.
        let exact = format!(
            "{{\"mode\":\"block\"}}{}",
            " ".repeat(MAX_CONTROL_BYTES - 16)
        );
        assert_eq!(exact.len(), MAX_CONTROL_BYTES);
        std::fs::write(&path, &exact).unwrap();
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        assert!(ctrl.status().oversized_file_replaced.is_none());
    }

    /// The file is over the limit and so is the document: it stays, and the refusal says the agents
    /// are not applying what the daemon holds in memory.
    #[test]
    fn a_file_over_the_limit_that_stays_over_says_the_agents_ignore_the_daemons_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let big = format!(
            "{{\"mode\":\"block\",\"policy\":\"{}\"}}",
            "a".repeat(MAX_CONTROL_BYTES)
        );
        std::fs::write(&path, &big).unwrap();

        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();

        let refused = ctrl.status().write_refused.expect("refused");
        assert_eq!(refused.change, "existing");
        assert!(!refused.agents_apply_state);
        assert!(
            refused.message.contains(&big.len().to_string())
                && refused
                    .message
                    .contains("not applying the daemon's in-memory state"),
            "{}",
            refused.message
        );
        assert!(ctrl.status().oversized_file_replaced.is_none());
    }

    /// A valid file over the limit whose re-serialised document is over it too stays on disk and
    /// ignored by the agents. A console change that is refused as well must not turn the status
    /// into "the agents apply the daemon's state": the file on disk is what decides.
    #[test]
    fn a_later_refusal_does_not_say_the_agents_apply_the_state_while_the_file_is_still_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let big = format!(
            "{{\"mode\":\"block\",\"policy\":\"{}\"}}",
            "a".repeat(MAX_CONTROL_BYTES)
        );
        std::fs::write(&path, &big).unwrap();
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        assert!(!ctrl.status().write_refused.unwrap().agents_apply_state);

        let mut toggles = BTreeMap::new();
        toggles.insert("sqli".to_string(), false);
        let err = ctrl.update(Some(Mode::Off), Some(toggles)).unwrap_err();
        assert!(err.downcast_ref::<ControlTooLarge>().is_some(), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), big, "untouched");

        let refused = ctrl.status().write_refused.unwrap();
        assert_eq!(refused.change, "update");
        assert!(!refused.agents_apply_state, "{}", refused.message);
        assert!(
            refused
                .message
                .contains("not applying the daemon's in-memory state"),
            "{}",
            refused.message
        );
        // The same for a cloud policy refused on top of it.
        assert!(
            ctrl.set_policy(Some("b".repeat(MAX_CONTROL_BYTES)))
                .is_err()
        );
        let refused = ctrl.status().write_refused.unwrap();
        assert_eq!(refused.change, "policy");
        assert!(!refused.agents_apply_state);
    }

    /// A file the agents read (within the limit) whose pretty-printed document is over it stays
    /// as it is, and the agents are still applying it.
    #[test]
    fn a_file_within_the_limit_that_grows_over_it_when_written_is_kept_and_still_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let compact = format!(
            "{{\"mode\":\"block\",\"policy\":\"{}\"}}",
            "a".repeat(MAX_CONTROL_BYTES - 40)
        );
        assert!(compact.len() <= MAX_CONTROL_BYTES);
        std::fs::write(&path, &compact).unwrap();

        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap(), compact);
        let refused = ctrl.status().write_refused.expect("refused");
        assert!(refused.agents_apply_state);
    }

    /// The same refused assignment, pulled again at every heartbeat, is logged and recorded once
    /// (the refusal is replaced exactly when it is logged); the size of the document does not
    /// identify it (the timestamp's width changes it), and another assignment is recorded anew.
    #[test]
    fn a_refused_policy_is_logged_once_per_assignment_not_per_size() {
        let dir = tempfile::tempdir().unwrap();
        let ctrl =
            Controller::load_or_init(&dir.path().join("control.json"), Mode::Monitor).unwrap();
        let big = "a".repeat(MAX_CONTROL_BYTES);
        let mut first = None;
        for extra in 0..4 {
            // A document of another size each time, for the same assignment.
            let text = format!("{big}{}", "b".repeat(extra));
            assert!(ctrl.set_policy_assigned(Some(text), Some("p1@3")).is_err());
            let refused = ctrl.status().write_refused.unwrap();
            assert_eq!(refused.identity.as_deref(), Some("p1@3"));
            let first = first.get_or_insert_with(|| (refused.size_bytes, refused.at.clone()));
            assert_eq!(
                (refused.size_bytes, &refused.at),
                (first.0, &first.1),
                "the refusal was recorded (and logged) again for the same assignment"
            );
        }

        // Another assignment is a new refusal.
        assert!(
            ctrl.set_policy_assigned(Some(big.clone()), Some("p1@4"))
                .is_err()
        );
        assert_eq!(
            ctrl.status().write_refused.unwrap().identity.as_deref(),
            Some("p1@4")
        );

        // Without an assignment the identity is a hash of the text: the same text is one
        // refusal, whatever size the document has, and another text is another.
        assert!(ctrl.set_policy(Some(format!("{big}x"))).is_err());
        let hashed = ctrl.status().write_refused.unwrap();
        assert!(hashed.identity.as_deref().unwrap().starts_with("sha:"));
        assert!(ctrl.set_policy(Some(format!("{big}x"))).is_err());
        assert_eq!(ctrl.status().write_refused.unwrap().at, hashed.at);
        assert!(ctrl.set_policy(Some(format!("{big}y"))).is_err());
        assert_ne!(
            ctrl.status().write_refused.unwrap().identity,
            hashed.identity
        );
    }

    /// When the policy the cloud wants becomes the installed one (the cloud reverts, or
    /// withdraws an assignment when none was installed), the refusal no longer applies.
    #[test]
    fn a_refusal_of_a_policy_clears_when_the_desired_state_is_the_installed_one() {
        let dir = tempfile::tempdir().unwrap();
        let ctrl =
            Controller::load_or_init(&dir.path().join("control.json"), Mode::Monitor).unwrap();
        assert!(ctrl.set_policy(Some("{\"version\":1}".into())).unwrap());
        assert!(
            ctrl.set_policy(Some("a".repeat(MAX_CONTROL_BYTES)))
                .is_err()
        );
        assert!(ctrl.policy_refused());

        // The cloud goes back to the installed policy: nothing to write, the refusal is over.
        assert!(!ctrl.set_policy(Some("{\"version\":1}".into())).unwrap());
        assert!(ctrl.status().write_refused.is_none());
        assert!(!ctrl.policy_refused());

        // No policy installed, a too large one refused, then the assignment is withdrawn.
        let ctrl = Controller::load_or_init(&dir.path().join("other.json"), Mode::Monitor).unwrap();
        assert!(
            ctrl.set_policy(Some("a".repeat(MAX_CONTROL_BYTES)))
                .is_err()
        );
        assert!(ctrl.policy_refused());
        assert!(!ctrl.set_policy(None).unwrap());
        assert!(ctrl.status().write_refused.is_none());
    }

    /// A refused console change is not a policy refusal: the cloud agreeing with the installed
    /// policy does not clear it.
    #[test]
    fn the_refusal_of_a_console_change_survives_an_unchanged_policy() {
        let dir = tempfile::tempdir().unwrap();
        let ctrl =
            Controller::load_or_init(&dir.path().join("control.json"), Mode::Monitor).unwrap();
        let policy = state_of_size(MAX_CONTROL_BYTES - 100).policy;
        assert!(ctrl.set_policy(policy.clone()).unwrap());
        let mut toggles = BTreeMap::new();
        toggles.insert("s".repeat(300), false);
        assert!(ctrl.update(None, Some(toggles)).is_err());
        assert!(!ctrl.set_policy(policy).unwrap());
        assert_eq!(ctrl.status().write_refused.unwrap().change, "update");
    }

    /// The view is the document and the refusal of the same moment. (That no writer can slip in
    /// between is by construction: writers record a refusal while they hold the state lock, which
    /// the view takes first; a test cannot hit so small a window reliably.)
    #[test]
    fn the_view_holds_the_document_and_the_refusal_together() {
        let dir = tempfile::tempdir().unwrap();
        let ctrl =
            Controller::load_or_init(&dir.path().join("control.json"), Mode::Monitor).unwrap();
        assert!(ctrl.set_policy(Some("small".into())).unwrap());
        assert!(
            ctrl.set_policy(Some("a".repeat(MAX_CONTROL_BYTES)))
                .is_err()
        );
        let (state, status) = ctrl.view();
        assert_eq!(state.policy.as_deref(), Some("small"));
        assert_eq!(state.revision, ctrl.snapshot().revision);
        assert_eq!(status, ctrl.status());
        assert_eq!(status.write_refused.unwrap().change, "policy");
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

    #[test]
    fn outside_request_reads_block_and_log_in_any_case_and_nothing_else() {
        for (text, want) in [
            ("block", Some(OutsideRequest::Block)),
            (" LOG\t", Some(OutsideRequest::Log)),
            ("Log", Some(OutsideRequest::Log)),
            ("monitor", None),
            ("off", None),
            ("", None),
        ] {
            assert_eq!(OutsideRequest::parse(text), want, "{text:?}");
        }
    }

    /// An `outside_request` nobody accepts, in a hand-edited file, is kept as found (the agents
    /// ignore it and keep the value they had) and the rest of the document applies; the daemon
    /// neither rewrites it as block nor reinitialises the document.
    #[test]
    fn an_unknown_outside_request_is_kept_as_found_and_the_rest_of_the_document_applies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        for found in [r#""sometimes""#, "true", "7"] {
            std::fs::write(
                &path,
                format!(r#"{{"mode":"block","outside_request":{found},"revision":7}}"#),
            )
            .unwrap();
            let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
            let state = ctrl.snapshot();
            assert_eq!(state.mode, Mode::Block, "{found}: not reinitialised");
            assert_eq!(state.revision, 7, "{found}");
            assert_eq!(
                state.host_outside_request(),
                HostOutsideRequest::Invalid,
                "{found}"
            );
            assert_eq!(
                state.outside_request_view().effective,
                "unchanged",
                "{found}"
            );
            let written: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let kept: serde_json::Value = serde_json::from_str(found).unwrap();
            assert_eq!(written["outside_request"], kept, "{found} kept as found");
        }
    }

    /// No member means no host setting: the daemon does not invent one, and the agents keep their
    /// start-up value (an agent started with outside_request=log stays log).
    #[test]
    fn a_document_without_outside_request_has_no_host_setting_and_none_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        for found in [
            r#"{"mode":"monitor","revision":3}"#,
            r#"{"mode":"monitor","outside_request":null,"revision":3}"#,
        ] {
            std::fs::write(&path, found).unwrap();
            let ctrl = Controller::load_or_init(&path, Mode::Off).unwrap();
            assert_eq!(
                ctrl.snapshot().host_outside_request(),
                HostOutsideRequest::Unset
            );
            assert_eq!(ctrl.snapshot().mode, Mode::Monitor);
            assert_eq!(ctrl.snapshot().outside_request_view().effective, "start-up");
            let written: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            assert!(
                written.get("outside_request").is_none(),
                "{found}: {written}"
            );
        }
    }

    /// A member named twice counts with its last value, as both agent engines read it, instead of
    /// the document being refused and reinitialised.
    #[test]
    fn a_member_named_twice_counts_with_its_last_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        std::fs::write(
            &path,
            r#"{"mode":"off","mode":"block","outside_request":"block","outside_request":"log","revision":9}"#,
        )
        .unwrap();
        let ctrl = Controller::load_or_init(&path, Mode::Monitor).unwrap();
        let state = ctrl.snapshot();
        assert_eq!(state.mode, Mode::Block);
        assert_eq!(
            state.host_outside_request(),
            HostOutsideRequest::Set(OutsideRequest::Log)
        );
        assert_eq!(state.revision, 9, "not reinitialised");
    }

    const POLICY_LOG: &str = r#"{"version":1,"config":{"hardening":{"outside_request":"log"}}}"#;

    /// The cloud's value travels inside the policy and leaves with it: withdrawing the policy, or
    /// replacing it with one that does not carry the setting, leaves no cloud value behind.
    #[test]
    fn withdrawing_or_replacing_the_policy_leaves_no_stale_cloud_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Block).unwrap();
        assert!(ctrl.set_policy(Some(POLICY_LOG.into())).unwrap());
        let view = ctrl.snapshot().outside_request_view();
        assert_eq!(
            (view.cloud, view.effective, view.source),
            (Some("log"), "log", "cloud")
        );
        assert_eq!(
            ctrl.snapshot().host_outside_request(),
            HostOutsideRequest::Unset,
            "not copied"
        );

        assert!(ctrl.set_policy(None).unwrap());
        let view = ctrl.snapshot().outside_request_view();
        assert_eq!(
            (view.cloud, view.effective),
            (None, "start-up"),
            "withdrawn"
        );

        assert!(ctrl.set_policy(Some(POLICY_LOG.into())).unwrap());
        for replacement in [
            r#"{"version":3}"#,
            r#"{"version":4,"config":{"hardening":{"outside_request":"sometimes"}}}"#,
            "not json",
        ] {
            assert!(ctrl.set_policy(Some(replacement.into())).unwrap());
            let view = ctrl.snapshot().outside_request_view();
            assert_eq!(
                (view.cloud, view.effective),
                (None, "start-up"),
                "{replacement}"
            );
        }
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(written.get("outside_request").is_none(), "{written}");
    }

    /// The host's value is its own: an unchanged policy and an unrelated policy edit keep it, the
    /// cloud never overwrites it, a cloud `log` still decides while it is in force, and the host
    /// can clear it.
    #[test]
    fn a_host_setting_stands_through_policy_changes_until_the_host_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.json");
        let ctrl = Controller::load_or_init(&path, Mode::Block).unwrap();
        ctrl.update_with(None, Some(Some(OutsideRequest::Log)), None)
            .unwrap();
        let rules = r#"{"version":1,"rules":[{"algorithm":"readFile_unwanted","action":"block"}]}"#;
        assert!(ctrl.set_policy(Some(rules.into())).unwrap());
        assert!(
            !ctrl.set_policy(Some(rules.into())).unwrap(),
            "unchanged policy"
        );
        let edited = r#"{"version":2,"rules":[{"algorithm":"sql_userinput","action":"block"}]}"#;
        assert!(
            ctrl.set_policy(Some(edited.into())).unwrap(),
            "unrelated edit"
        );
        let view = ctrl.snapshot().outside_request_view();
        assert_eq!(
            (view.host, view.effective, view.source),
            (Some("log"), "log", "host")
        );

        ctrl.update_with(None, Some(Some(OutsideRequest::Block)), None)
            .unwrap();
        assert!(ctrl.set_policy(Some(POLICY_LOG.into())).unwrap());
        let view = ctrl.snapshot().outside_request_view();
        assert_eq!(
            (view.host, view.cloud, view.effective, view.source),
            (Some("block"), Some("log"), "log", "cloud"),
            "both must allow blocking: the cloud's log decides, the host's block is kept"
        );
        assert!(ctrl.set_policy(None).unwrap());
        let view = ctrl.snapshot().outside_request_view();
        assert_eq!(
            (view.host, view.effective),
            (Some("block"), "block"),
            "the host's again"
        );

        ctrl.update_with(None, Some(None), None).unwrap();
        assert_eq!(
            ctrl.snapshot().host_outside_request(),
            HostOutsideRequest::Unset,
            "cleared"
        );
        let written: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(written.get("outside_request").is_none(), "{written}");

        // A restart reads the host's value back unchanged.
        ctrl.update_with(None, Some(Some(OutsideRequest::Log)), None)
            .unwrap();
        let reloaded = Controller::load_or_init(&path, Mode::Off).unwrap();
        assert_eq!(
            reloaded.snapshot().host_outside_request(),
            HostOutsideRequest::Set(OutsideRequest::Log)
        );
    }
}
