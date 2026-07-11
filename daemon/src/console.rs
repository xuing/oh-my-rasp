//! Local single-host console: a small HTTP surface that renders the embedded
//! dashboard and exposes JSON APIs for live attack logs, statistics, the
//! business-latency panel, and the algorithm/mode controls.
//!
//! It is intentionally dependency-light: one embedded HTML page that polls a
//! handful of JSON endpoints. No build step, no external assets.

use std::collections::BTreeMap;
use std::sync::Arc;

use std::fmt::Write as _;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::control::{ControlState, Controller, Mode};
use crate::store::EventStore;
use crate::uploader::{CloudStatus, CloudStatusHandle};

/// Prometheus text exposition content type (version 0.0.4).
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Shared application state handed to every console handler.
pub struct AppState {
    pub store: Arc<EventStore>,
    pub controller: Arc<Controller>,
    pub cloud_status: CloudStatusHandle,
    pub spool_path: String,
    pub control_path: String,
    pub version: &'static str,
}

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/api/events", get(events))
        .route("/api/stats", get(stats))
        .route("/api/control", get(control_get).post(control_post))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn healthz() -> &'static str {
    "ok"
}

/// Prometheus metrics endpoint. Exposes the cloud forwarder's drop/fail/upload
/// counters so an operator can alert on event loss — the same counters the
/// console shows as JSON, in the text exposition format scrapers understand.
async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = render_metrics(&state.cloud_status.snapshot());
    ([(CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)], body)
}

/// Render the cloud status as Prometheus text exposition format.
fn render_metrics(status: &CloudStatus) -> String {
    let mut out = String::with_capacity(1024);
    let mut gauge = |name: &str, help: &str, value: i64| {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} gauge");
        let _ = writeln!(out, "{name} {value}");
    };
    gauge(
        "ohmyrasp_cloud_enabled",
        "Whether the cloud uplink is enabled (1) or the daemon runs standalone (0).",
        status.enabled as i64,
    );
    gauge(
        "ohmyrasp_cloud_connected",
        "Whether the last cloud interaction succeeded (1) or failed (0).",
        status.connected as i64,
    );
    gauge(
        "ohmyrasp_cloud_registered",
        "Whether the daemon has registered an agent identity with the control plane.",
        status.registered as i64,
    );
    gauge(
        "ohmyrasp_cloud_policy_version",
        "Version of the cloud-assigned policy currently held.",
        status.policy_version,
    );
    gauge(
        "ohmyrasp_events_pending",
        "Detection events buffered in memory awaiting upload.",
        status.pending as i64,
    );

    let mut counter = |name: &str, help: &str, value: u64| {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        let _ = writeln!(out, "{name} {value}");
    };
    counter(
        "ohmyrasp_events_uploaded_total",
        "Detection events successfully uploaded to the cloud control plane.",
        status.uploaded_total,
    );
    counter(
        "ohmyrasp_events_failed_total",
        "Upload attempts that failed and were retried.",
        status.failed_total,
    );
    counter(
        "ohmyrasp_events_dropped_total",
        "Detection events dropped because the retry buffer was full.",
        status.dropped_total,
    );
    out
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    hook: Option<String>,
    action: Option<String>,
}

async fn events(State(state): State<Arc<AppState>>, Query(q): Query<EventsQuery>) -> Json<Value> {
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let hook = q.hook.as_deref().filter(|s| !s.is_empty());
    let action = q.action.as_deref().filter(|s| !s.is_empty());
    let events = state.store.recent(limit, hook, action);
    Json(json!({ "events": events, "count": events.len() }))
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "stats": state.store.stats(),
        "cloud": state.cloud_status.snapshot(),
        "control": state.controller.snapshot(),
        "spool_path": state.spool_path,
        "control_path": state.control_path,
        "version": state.version,
    }))
}

async fn control_get(State(state): State<Arc<AppState>>) -> Json<ControlState> {
    Json(state.controller.snapshot())
}

#[derive(Debug, Deserialize)]
struct ControlUpdate {
    mode: Option<String>,
    #[serde(default)]
    algorithms: Option<BTreeMap<String, bool>>,
}

#[derive(Debug, Serialize)]
struct ApiError {
    error: String,
}

async fn control_post(
    State(state): State<Arc<AppState>>,
    Json(update): Json<ControlUpdate>,
) -> Result<Json<ControlState>, (StatusCode, Json<ApiError>)> {
    let mode = match &update.mode {
        Some(raw) => match Mode::parse(raw) {
            Some(m) => Some(m),
            None => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiError {
                        error: format!("invalid mode: {raw}"),
                    }),
                ));
            }
        },
        None => None,
    };
    state
        .controller
        .update(mode, update.algorithms)
        .map(Json)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: err.to_string(),
                }),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    #[test]
    fn render_metrics_emits_prometheus_lines() {
        let status = CloudStatus {
            enabled: true,
            connected: true,
            registered: true,
            policy_version: 4,
            pending: 5,
            uploaded_total: 12,
            failed_total: 2,
            dropped_total: 7,
            ..Default::default()
        };
        let text = render_metrics(&status);
        assert!(text.contains("# TYPE ohmyrasp_events_dropped_total counter"));
        assert!(text.contains("ohmyrasp_events_dropped_total 7"));
        assert!(text.contains("ohmyrasp_events_uploaded_total 12"));
        assert!(text.contains("ohmyrasp_events_failed_total 2"));
        assert!(text.contains("ohmyrasp_events_pending 5"));
        assert!(text.contains("ohmyrasp_cloud_enabled 1"));
        assert!(text.contains("ohmyrasp_cloud_policy_version 4"));
    }

    fn test_state() -> Arc<AppState> {
        let dir = tempfile::tempdir().unwrap();
        let controller =
            Controller::load_or_init(&dir.path().join("control.json"), Mode::Monitor).unwrap();
        Arc::new(AppState {
            store: Arc::new(EventStore::new(10)),
            controller: Arc::new(controller),
            cloud_status: CloudStatusHandle::new(true),
            spool_path: "/tmp/spool".into(),
            control_path: "/tmp/control".into(),
            version: "test",
        })
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_200_and_expected_metric() {
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp.headers().get(CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(content_type.starts_with("text/plain"), "got {content_type}");

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            text.contains("ohmyrasp_events_dropped_total"),
            "metrics body missing drop counter: {text}"
        );
    }
}
