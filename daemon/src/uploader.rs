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
        installed_policy: None,
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
    /// The assignment of the policy the control file holds, as far as this run knows it.
    installed_policy: Option<PolicyRef>,
}

/// A policy assignment as the cloud reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PolicyRef {
    id: Option<String>,
    version: i64,
}

/// The policy to report upstream. With a control file to write, that is the one last written to
/// it successfully (`installed`, nothing when none is known), whatever the cloud assigns: an
/// assignment the daemon refused, or could not pull, is not applied, and whether a refusal is
/// outstanding at this moment does not change what the file holds. Without a control file the
/// daemon applies nothing and reports the assignment.
fn reported_policy(
    assigned: PolicyRef,
    installed: Option<&PolicyRef>,
    has_control_file: bool,
) -> PolicyRef {
    if has_control_file {
        installed.cloned().unwrap_or_default()
    } else {
        assigned
    }
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
                let assigned = PolicyRef {
                    id: assignment.policy_id,
                    version: assignment.policy_version,
                };
                let reported = self.settle_policy(assigned).await;
                self.identity.policy_id = reported.id.clone();
                self.identity.policy_version = reported.version;
                self.status.update(|s| {
                    s.registered = true;
                    s.connected = true;
                    s.agent_id = self.identity.agent_id.clone();
                    s.policy_id = reported.id;
                    s.policy_version = reported.version;
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
    }

    async fn heartbeat(&mut self) {
        let Some(client) = &self.client else { return };
        if self.identity.agent_id.is_empty() {
            return;
        }
        match client.heartbeat(&self.identity.agent_id).await {
            Ok(assignment) => {
                let assigned = PolicyRef {
                    id: assignment.policy_id,
                    version: assignment.policy_version,
                };
                let reported = self.settle_policy(assigned).await;
                // With a control file, what is reported is what it holds, which is also true when
                // that is nothing (a withdrawn policy); without one, the assignment is only
                // reported when it names a policy.
                if self.controller.is_some() || reported.id.is_some() {
                    self.identity.policy_id = reported.id.clone();
                    self.identity.policy_version = reported.version;
                }
                self.status.update(|s| {
                    s.connected = true;
                    s.policy_id = reported.id;
                    if self.controller.is_some() || reported.version > 0 {
                        s.policy_version = reported.version;
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
    }

    /// Hand the policy the cloud assigns to the control file, and return the policy to report
    /// upstream: the one last written to the control file successfully, see [`reported_policy`].
    /// A policy the daemon refuses to install (the control file would be larger than the agents
    /// read), or cannot pull, is assigned but not applied. The upload schema has no way to say
    /// "assigned, but refused": that is reported locally, as `control_status.write_refused`.
    async fn settle_policy(&mut self, assigned: PolicyRef) -> PolicyRef {
        self.refresh_policy(&assigned).await;
        reported_policy(
            assigned,
            self.installed_policy.as_ref(),
            self.controller.is_some(),
        )
    }

    /// Pull the cloud-assigned policy and hand it to the control file for the
    /// agent to install. Idempotent on the controller side, so it can run on
    /// every heartbeat without churning the file. `installed_policy` changes only when the file
    /// holds the pulled policy afterwards: a pull that fails, or a write that is refused, leaves it.
    async fn refresh_policy(&mut self, assigned: &PolicyRef) {
        let (Some(client), Some(controller)) = (&self.client, &self.controller) else {
            return;
        };
        if self.identity.agent_id.is_empty() {
            return;
        }
        match client.pull_policy(&self.identity.agent_id).await {
            Ok(policy) => {
                let has_policy = policy.is_some();
                let assignment = assigned
                    .id
                    .as_ref()
                    .map(|id| format!("{id}@{}", assigned.version));
                match controller.set_policy_assigned(policy, assignment.as_deref()) {
                    Ok(changed) => {
                        if changed {
                            tracing::info!("distributed updated policy to the control file");
                        }
                        self.installed_policy = has_policy.then(|| assigned.clone());
                    }
                    // The controller has already logged the refusal and kept it for the status
                    // views.
                    Err(err)
                        if err
                            .downcast_ref::<crate::control::ControlTooLarge>()
                            .is_some() => {}
                    Err(err) => tracing::warn!(%err, "failed to write policy to control file"),
                }
            }
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
            // An outbox an earlier daemon wrote can hold lines it should not have queued, such as
            // an agent start line: only detections are uploaded.
            if let Some(event) = AgentEvent::parse_line(0, now_rfc3339(), line)
                && event.is_detection()
            {
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
    use crate::cloud::CloudClient;

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
            installed_policy: None,
        }
    }

    fn event(seq: u64) -> AgentEvent {
        let line =
            format!("{{\"hook\":\"sql\",\"algorithm\":\"sqli\",\"action\":\"log\",\"seq\":{seq}}}");
        AgentEvent::parse_line(seq, now_rfc3339(), &line).expect("event parses")
    }

    fn assignment(id: &str, version: i64) -> PolicyRef {
        PolicyRef {
            id: Some(id.into()),
            version,
        }
    }

    #[test]
    fn the_reported_policy_is_the_installed_one_whatever_is_assigned() {
        let installed = assignment("p1", 1);
        assert_eq!(
            reported_policy(assignment("p2", 2), Some(&installed), true),
            installed
        );
        // Nothing installed yet: no version is claimed.
        assert_eq!(
            reported_policy(assignment("p2", 2), None, true),
            PolicyRef::default()
        );
        // No control file: the daemon applies nothing and reports the assignment.
        assert_eq!(
            reported_policy(assignment("p2", 2), None, false),
            assignment("p2", 2)
        );
    }

    /// What the cloud control plane answers, set by the test between heartbeats.
    #[derive(Default)]
    struct Mock {
        version: i64,
        policy: String,
        /// The policy request fails with a 500.
        fail_policy: bool,
        uploads: Vec<serde_json::Value>,
    }

    /// A control plane on a loopback port: registers as `a1`, answers heartbeats with the
    /// assigned policy `p<version>`, serves `policy` and records the uploads.
    async fn mock_control_plane(mock: std::sync::Arc<Mutex<Mock>>) -> std::net::SocketAddr {
        use axum::extract::State;
        use axum::routing::{get, post};
        use axum::{Json, Router};
        type Shared = State<std::sync::Arc<Mutex<Mock>>>;
        let assignment = |state: &Mutex<Mock>| {
            let mock = state.lock().unwrap();
            serde_json::json!({
                "id": "a1",
                "policy_id": format!("p{}", mock.version),
                "policy_version": mock.version,
            })
        };
        let app = Router::new()
            .route(
                "/api/v1/agents/register",
                post(move |State(state): Shared| async move { Json(assignment(&state)) }),
            )
            .route(
                "/api/v1/agents/{id}/heartbeat",
                post(move |State(state): Shared| async move { Json(assignment(&state)) }),
            )
            .route(
                "/api/v1/agents/{id}/policy",
                get(|State(state): Shared| async move {
                    let mock = state.lock().unwrap();
                    if mock.fail_policy {
                        (axum::http::StatusCode::INTERNAL_SERVER_ERROR, String::new())
                    } else {
                        (axum::http::StatusCode::OK, mock.policy.clone())
                    }
                }),
            )
            .route(
                "/api/v1/events/attack",
                post(
                    |State(state): Shared, Json(body): Json<serde_json::Value>| async move {
                        state.lock().unwrap().uploads.push(body);
                    },
                ),
            )
            .with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// The cloud assigns a policy the daemon cannot install: the control file keeps the previous
    /// one, and what is reported upstream (the status, the upload body) is the installed version.
    /// Once the cloud goes back to the installed policy, the refusal is over.
    #[tokio::test]
    async fn a_refused_policy_is_not_reported_as_the_active_version() {
        use std::sync::Arc;
        let mock = Arc::new(Mutex::new(Mock {
            version: 1,
            policy: "{\"version\":1}".into(),
            fail_policy: false,
            uploads: Vec::new(),
        }));
        let addr = mock_control_plane(mock.clone()).await;
        let dir = tempfile::tempdir().unwrap();
        let control_path = dir.path().join("control.json");
        let controller = Arc::new(
            crate::control::Controller::load_or_init(&control_path, crate::control::Mode::Monitor)
                .unwrap(),
        );
        let cfg = CloudConfig {
            enabled: true,
            backend_url: format!("http://{addr}"),
            app_id: "app".into(),
            ..CloudConfig::default()
        };
        let mut up = uploader(dir.path().join("outbox.ndjson"), 10);
        up.client = Some(CloudClient::new(cfg).unwrap());
        up.controller = Some(controller.clone());

        up.ensure_registered().await;
        assert_eq!(up.status.snapshot().policy_version, 1);
        assert_eq!(
            controller.snapshot().policy.as_deref(),
            Some("{\"version\":1}")
        );

        // Version 2 is assigned, and is too large to install.
        {
            let mut mock = mock.lock().unwrap();
            mock.version = 2;
            mock.policy = "a".repeat(crate::control::MAX_CONTROL_BYTES);
        }
        up.heartbeat().await;
        let status = up.status.snapshot();
        assert_eq!(
            status.policy_version, 1,
            "the installed version, not the refused one"
        );
        assert_eq!(status.policy_id.as_deref(), Some("p1"));
        assert_eq!(up.identity.policy_version, 1);
        assert!(controller.policy_refused());
        assert_eq!(
            controller.snapshot().policy.as_deref(),
            Some("{\"version\":1}")
        );

        up.enqueue(event(1));
        up.flush().await;
        let body = mock.lock().unwrap().uploads.pop().expect("an upload");
        assert_eq!(body["policy_version"], serde_json::json!(1), "{body}");
        assert_eq!(body["policy_id"], serde_json::json!("p1"), "{body}");

        // The cloud reverts to the installed policy: the refusal indicator clears.
        {
            let mut mock = mock.lock().unwrap();
            mock.version = 1;
            mock.policy = "{\"version\":1}".into();
        }
        up.heartbeat().await;
        assert!(!controller.policy_refused());
        assert!(controller.status().write_refused.is_none());
        assert_eq!(up.status.snapshot().policy_version, 1);
    }

    /// An uploader registered with a mock control plane that serves `{"version":1}` as `p1`.
    async fn registered_uploader(
        dir: &std::path::Path,
    ) -> (
        Uploader,
        std::sync::Arc<Mutex<Mock>>,
        std::sync::Arc<crate::control::Controller>,
    ) {
        use std::sync::Arc;
        let mock = Arc::new(Mutex::new(Mock {
            version: 1,
            policy: "{\"version\":1}".into(),
            ..Mock::default()
        }));
        let addr = mock_control_plane(mock.clone()).await;
        let controller = Arc::new(
            crate::control::Controller::load_or_init(
                &dir.join("control.json"),
                crate::control::Mode::Monitor,
            )
            .unwrap(),
        );
        let cfg = CloudConfig {
            enabled: true,
            backend_url: format!("http://{addr}"),
            app_id: "app".into(),
            ..CloudConfig::default()
        };
        let mut up = uploader(dir.join("outbox.ndjson"), 10);
        up.client = Some(CloudClient::new(cfg).unwrap());
        up.controller = Some(controller.clone());
        up.ensure_registered().await;
        assert_eq!(up.status.snapshot().policy_version, 1);
        (up, mock, controller)
    }

    /// What the next upload says about the policy: (policy_id, policy_version).
    async fn uploaded_policy(
        up: &mut Uploader,
        mock: &std::sync::Arc<Mutex<Mock>>,
    ) -> (serde_json::Value, serde_json::Value) {
        up.enqueue(event(1));
        up.flush().await;
        let body = mock.lock().unwrap().uploads.pop().expect("an upload");
        (body["policy_id"].clone(), body["policy_version"].clone())
    }

    /// v1 is installed, the heartbeat assigns v2, and the policy request fails: nothing was
    /// written, so v1 is still what is reported (status and uploads).
    #[tokio::test]
    async fn a_failed_policy_pull_after_a_new_assignment_still_reports_the_installed_version() {
        let dir = tempfile::tempdir().unwrap();
        let (mut up, mock, controller) = registered_uploader(dir.path()).await;
        {
            let mut mock = mock.lock().unwrap();
            mock.version = 2;
            mock.fail_policy = true;
        }
        up.heartbeat().await;
        assert_eq!(up.status.snapshot().policy_version, 1);
        assert_eq!(up.status.snapshot().policy_id.as_deref(), Some("p1"));
        assert_eq!(
            controller.snapshot().policy.as_deref(),
            Some("{\"version\":1}")
        );
        let (id, version) = uploaded_policy(&mut up, &mock).await;
        assert_eq!(
            (id, version),
            (serde_json::json!("p1"), serde_json::json!(1))
        );
    }

    /// v2 is refused for size; a console write succeeds and clears the refusal; the next policy
    /// request fails. The control file still holds v1, and v1 is what is reported.
    #[tokio::test]
    async fn a_console_write_clearing_a_refusal_does_not_make_the_refused_version_active() {
        let dir = tempfile::tempdir().unwrap();
        let (mut up, mock, controller) = registered_uploader(dir.path()).await;
        {
            let mut mock = mock.lock().unwrap();
            mock.version = 2;
            mock.policy = "a".repeat(crate::control::MAX_CONTROL_BYTES);
        }
        up.heartbeat().await;
        assert!(controller.policy_refused());

        controller
            .update(Some(crate::control::Mode::Block), None)
            .unwrap();
        assert!(
            !controller.policy_refused(),
            "the write cleared the refusal"
        );

        mock.lock().unwrap().fail_policy = true;
        up.heartbeat().await;
        assert_eq!(up.status.snapshot().policy_version, 1);
        assert_eq!(up.identity.policy_version, 1);
        let (id, version) = uploaded_policy(&mut up, &mock).await;
        assert_eq!(
            (id, version),
            (serde_json::json!("p1"), serde_json::json!(1))
        );
        assert_eq!(
            controller.snapshot().policy.as_deref(),
            Some("{\"version\":1}")
        );
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

    /// An outbox written by a daemon that queued start lines as detections: only detections
    /// come back.
    #[test]
    fn load_outbox_skips_lines_that_are_not_detections() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outbox.ndjson");
        std::fs::write(
            &path,
            concat!(
                "{\"event\":\"ohmyrasp-java8-agent-start\",\"java_version\":\"1.8.0_402\"}\n",
                "{\"event\":\"ohmyrasp-detection\",\"timestamp\":1767225600000,\"hook\":\"h\",\"algorithm\":\"a\",\"action\":\"log\"}\n",
                "{\"kind\":\"diagnostic\",\"hook\":\"h\"}\n",
            ),
        )
        .unwrap();
        let mut up = uploader(path, 10);
        up.load_outbox();
        assert_eq!(up.pending.len(), 1);
        assert_eq!(up.pending[0].timestamp, "2026-01-01T00:00:00Z");
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
