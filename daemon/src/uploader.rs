//! Cloud forwarder with offline buffering.
//!
//! Owns the cloud identity lifecycle (register + periodic heartbeat) and ships
//! enriched detection events to the control plane. When the cloud is disabled or
//! unreachable, events accumulate in a bounded, disk-backed outbox and are
//! replayed once connectivity returns — this is the "offline + realtime" duality
//! the project asked for.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::mpsc;
use tokio::time::{MissedTickBehavior, interval};

use crate::cloud::CloudClient;
use crate::config::{BufferConfig, CloudConfig};
use crate::model::{AgentEvent, CloudIdentity};
use crate::util::now_rfc3339;

/// Observable cloud status for the console.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CloudStatus {
    pub enabled: bool,
    pub connected: bool,
    pub registered: bool,
    pub agent_id: String,
    pub policy_id: Option<String>,
    pub policy_version: i64,
    pub pending: usize,
    pub uploaded_total: u64,
    pub failed_total: u64,
    pub dropped_total: u64,
    pub last_error: Option<String>,
    pub last_upload_at: Option<String>,
    pub last_heartbeat_at: Option<String>,
}

/// Shared, cheaply-cloneable handle to the live cloud status.
#[derive(Clone)]
pub struct CloudStatusHandle(std::sync::Arc<Mutex<CloudStatus>>);

impl CloudStatusHandle {
    pub fn new(enabled: bool) -> Self {
        let status = CloudStatus {
            enabled,
            ..Default::default()
        };
        Self(std::sync::Arc::new(Mutex::new(status)))
    }

    pub fn snapshot(&self) -> CloudStatus {
        self.0.lock().expect("status mutex").clone()
    }

    fn update(&self, f: impl FnOnce(&mut CloudStatus)) {
        f(&mut self.0.lock().expect("status mutex"));
    }
}

/// Handle the rest of the program uses to feed the uploader.
pub struct UploaderHandle {
    tx: mpsc::Sender<AgentEvent>,
    status: CloudStatusHandle,
}

impl UploaderHandle {
    pub fn status(&self) -> &CloudStatusHandle {
        &self.status
    }

    /// Offer a detection to the uploader. Never blocks the caller: if the
    /// channel is full the event is dropped (and counted) rather than stall
    /// ingestion.
    pub fn offer(&self, event: AgentEvent) {
        if let Err(err) = self.tx.try_send(event)
            && matches!(err, mpsc::error::TrySendError::Full(_))
        {
            self.status.update(|s| s.dropped_total += 1);
        }
    }
}

/// Spawn the uploader task. When `client` is `None` the daemon runs offline:
/// events still flow into the disk outbox (capped) so nothing is silently lost
/// while standalone. Returns the feed handle plus the task's `JoinHandle` so the
/// caller can await a clean drain on shutdown.
pub fn spawn(
    cloud_cfg: CloudConfig,
    buffer_cfg: BufferConfig,
    client: Option<CloudClient>,
    controller: Option<std::sync::Arc<crate::control::Controller>>,
) -> (UploaderHandle, tokio::task::JoinHandle<()>) {
    let status = CloudStatusHandle::new(cloud_cfg.enabled);
    let (tx, rx) = mpsc::channel::<AgentEvent>(4096);
    let task = Uploader {
        cfg: cloud_cfg,
        outbox_path: buffer_cfg.dir.join("outbox.ndjson"),
        max_pending: buffer_cfg.max_pending.max(1),
        client,
        controller,
        identity: CloudIdentity::default(),
        pending: VecDeque::new(),
        status: status.clone(),
    };
    let join = tokio::spawn(task.run(rx));
    (UploaderHandle { tx, status }, join)
}

struct Uploader {
    cfg: CloudConfig,
    outbox_path: PathBuf,
    max_pending: usize,
    client: Option<CloudClient>,
    controller: Option<std::sync::Arc<crate::control::Controller>>,
    identity: CloudIdentity,
    pending: VecDeque<AgentEvent>,
    status: CloudStatusHandle,
}

impl Uploader {
    async fn run(mut self, mut rx: mpsc::Receiver<AgentEvent>) {
        self.identity.app_id = self.cfg.app_id.clone();
        self.identity.environment_id = self.cfg.environment_id.clone();
        self.load_outbox();

        let mut upload_tick = interval(Duration::from_millis(self.cfg.upload_interval_ms.max(100)));
        upload_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut hb_tick = interval(Duration::from_secs(self.cfg.heartbeat_interval_s.max(5)));
        hb_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(event) => self.enqueue(event),
                        None => break, // all senders dropped → shutting down
                    }
                }
                _ = upload_tick.tick() => {
                    self.ensure_registered().await;
                    self.flush().await;
                }
                _ = hb_tick.tick() => {
                    self.heartbeat().await;
                }
            }
            self.publish_counts();
        }

        // Drain whatever is queued, then persist the remainder durably.
        while let Ok(event) = rx.try_recv() {
            self.enqueue(event);
        }
        self.ensure_registered().await;
        self.flush().await;
        self.persist_outbox();
        self.publish_counts();
    }

    // TODO(durability): pending events live only in memory and are flushed to
    // the on-disk outbox by `persist_outbox` on a *graceful* shutdown. A hard
    // crash (SIGKILL, panic, power loss) therefore loses everything currently
    // buffered. A crash-durable design would append each event to the outbox as
    // it is enqueued (a write-ahead log) and compact it on successful upload,
    // rather than writing the whole queue once at exit. Deferred because it must
    // be covered by crash-consistency tests; see the "crash-durable-outbox"
    // finding.
    fn enqueue(&mut self, event: AgentEvent) {
        self.pending.push_back(event);
        while self.pending.len() > self.max_pending {
            self.pending.pop_front();
            self.status.update(|s| s.dropped_total += 1);
        }
    }

    async fn ensure_registered(&mut self) {
        let Some(client) = &self.client else { return };
        if !self.identity.agent_id.is_empty() {
            return;
        }
        match client.register().await {
            Ok(assignment) => {
                if let Some(id) = assignment.agent_id {
                    self.identity.agent_id = id;
                }
                self.identity.policy_id = assignment.policy_id;
                self.identity.policy_version = assignment.policy_version;
                self.status.update(|s| {
                    s.registered = true;
                    s.connected = true;
                    s.agent_id = self.identity.agent_id.clone();
                    s.policy_id = self.identity.policy_id.clone();
                    s.policy_version = self.identity.policy_version;
                    s.last_error = None;
                });
                tracing::info!(agent_id = %self.identity.agent_id, "registered with control plane");
            }
            Err(err) => {
                self.status.update(|s| {
                    s.connected = false;
                    s.last_error = Some(format!("register: {err}"));
                });
                tracing::warn!(%err, "control-plane registration failed; buffering events");
            }
        }
        self.refresh_policy().await;
    }

    async fn heartbeat(&mut self) {
        let Some(client) = &self.client else { return };
        if self.identity.agent_id.is_empty() {
            return;
        }
        match client.heartbeat(&self.identity.agent_id).await {
            Ok(assignment) => {
                if assignment.policy_id.is_some() {
                    self.identity.policy_id = assignment.policy_id.clone();
                    self.identity.policy_version = assignment.policy_version;
                }
                self.status.update(|s| {
                    s.connected = true;
                    s.policy_id = assignment.policy_id;
                    if assignment.policy_version > 0 {
                        s.policy_version = assignment.policy_version;
                    }
                    s.last_heartbeat_at = Some(now_rfc3339());
                    s.last_error = None;
                });
            }
            Err(err) => {
                self.status.update(|s| {
                    s.connected = false;
                    s.last_error = Some(format!("heartbeat: {err}"));
                });
            }
        }
        self.refresh_policy().await;
    }

    /// Pull the cloud-assigned policy and hand it to the control file for the
    /// agent to install. Idempotent on the controller side, so it can run on
    /// every heartbeat without churning the file.
    async fn refresh_policy(&self) {
        let (Some(client), Some(controller)) = (&self.client, &self.controller) else {
            return;
        };
        if self.identity.agent_id.is_empty() {
            return;
        }
        match client.pull_policy(&self.identity.agent_id).await {
            Ok(policy) => match controller.set_policy(policy) {
                Ok(true) => tracing::info!("distributed updated policy to the control file"),
                Ok(false) => {}
                Err(err) => tracing::warn!(%err, "failed to write policy to control file"),
            },
            Err(err) => tracing::debug!(%err, "policy pull failed; keeping last policy"),
        }
    }

    async fn flush(&mut self) {
        let Some(client) = &self.client else { return };
        if self.identity.agent_id.is_empty() || self.pending.is_empty() {
            return;
        }
        let batch_max = self.cfg.upload_batch_max.max(1);
        let mut sent = 0u64;
        while sent < batch_max as u64 {
            let Some(front) = self.pending.front() else {
                break;
            };
            let body = front.to_cloud_attack(&self.identity);
            match client.upload_attack(&body).await {
                Ok(()) => {
                    self.pending.pop_front();
                    sent += 1;
                }
                Err(err) => {
                    self.status.update(|s| {
                        s.connected = false;
                        s.failed_total += 1;
                        s.last_error = Some(format!("upload: {err}"));
                    });
                    tracing::debug!(%err, "upload failed; will retry");
                    break;
                }
            }
        }
        if sent > 0 {
            self.status.update(|s| {
                s.connected = true;
                s.uploaded_total += sent;
                s.last_upload_at = Some(now_rfc3339());
                s.last_error = None;
            });
        }
    }

    fn publish_counts(&self) {
        let pending = self.pending.len();
        self.status.update(|s| s.pending = pending);
    }

    fn load_outbox(&mut self) {
        let Ok(text) = std::fs::read_to_string(&self.outbox_path) else {
            return;
        };
        let mut restored = 0usize;
        for line in text.lines() {
            if let Some(event) = AgentEvent::parse_line(0, now_rfc3339(), line) {
                self.enqueue(event);
                restored += 1;
            }
        }
        if restored > 0 {
            tracing::info!(restored, "restored events from offline outbox");
        }
        // The replayed file is now owned in memory; clear it to avoid duplicates.
        let _ = std::fs::remove_file(&self.outbox_path);
    }

    fn persist_outbox(&self) {
        if self.pending.is_empty() {
            return;
        }
        if let Some(parent) = self.outbox_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut buf = String::with_capacity(self.pending.len() * 256);
        for event in &self.pending {
            // Persist the original raw line so it can be re-enriched on restart.
            if let Ok(line) = serde_json::to_string(&event.raw) {
                buf.push_str(&line);
                buf.push('\n');
            }
        }
        if let Err(err) = std::fs::write(&self.outbox_path, buf.as_bytes()) {
            tracing::warn!(%err, path = %self.outbox_path.display(), "failed to persist outbox");
        } else {
            // The outbox holds raw attack request context; keep it owner-only
            // rather than the umask default of world-readable.
            if let Err(err) = crate::util::restrict_to_owner(&self.outbox_path) {
                tracing::warn!(%err, path = %self.outbox_path.display(), "failed to restrict outbox permissions");
            }
            tracing::info!(
                count = self.pending.len(),
                "persisted pending events to outbox"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a bare uploader with no cloud client for exercising the pure,
    /// server-free buffering logic (enqueue eviction, outbox persist/load).
    fn uploader(outbox_path: PathBuf, max_pending: usize) -> Uploader {
        Uploader {
            cfg: CloudConfig::default(),
            outbox_path,
            max_pending,
            client: None,
            controller: None,
            identity: CloudIdentity::default(),
            pending: VecDeque::new(),
            status: CloudStatusHandle::new(false),
        }
    }

    fn event(seq: u64) -> AgentEvent {
        let line =
            format!("{{\"hook\":\"sql\",\"algorithm\":\"sqli\",\"action\":\"log\",\"seq\":{seq}}}");
        AgentEvent::parse_line(seq, now_rfc3339(), &line).expect("event parses")
    }

    #[test]
    fn enqueue_evicts_oldest_and_counts_drops() {
        let dir = tempfile::tempdir().unwrap();
        let mut up = uploader(dir.path().join("outbox.ndjson"), 2);
        for seq in 1..=4 {
            up.enqueue(event(seq));
        }
        // Bounded at max_pending; the two oldest were dropped and counted.
        assert_eq!(up.pending.len(), 2);
        assert_eq!(up.status.snapshot().dropped_total, 2);
        // The survivors are the two most recent (3 and 4).
        assert_eq!(up.pending.front().unwrap().seq, 3);
        assert_eq!(up.pending.back().unwrap().seq, 4);
    }

    #[test]
    fn outbox_round_trips_pending_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.ndjson");

        let mut writer = uploader(path.clone(), 10);
        writer.enqueue(event(1));
        writer.enqueue(event(2));
        writer.persist_outbox();
        assert!(path.exists());

        // A fresh uploader restores the persisted events and clears the file so
        // a later run doesn't double-count them.
        let mut reader = uploader(path.clone(), 10);
        reader.load_outbox();
        assert_eq!(reader.pending.len(), 2);
        assert!(!path.exists(), "outbox consumed on load");
    }

    #[test]
    fn persist_outbox_skips_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.ndjson");
        let up = uploader(path.clone(), 10);
        up.persist_outbox();
        assert!(!path.exists(), "no file written for an empty outbox");
    }

    #[cfg(unix)]
    #[test]
    fn persisted_outbox_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.ndjson");
        let mut up = uploader(path.clone(), 10);
        up.enqueue(event(1));
        up.persist_outbox();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
