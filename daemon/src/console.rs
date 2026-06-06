//! Local single-host console: a small HTTP surface that renders the embedded
//! dashboard and exposes JSON APIs for live attack logs, statistics, the
//! business-latency panel, and the algorithm/mode controls.
//!
//! It is intentionally dependency-light: one embedded HTML page that polls a
//! handful of JSON endpoints. No build step, no external assets.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::get;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::control::{ControlState, Controller, Mode};
use crate::store::EventStore;
use crate::uploader::CloudStatusHandle;

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
                    Json(ApiError { error: format!("invalid mode: {raw}") }),
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
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: err.to_string() }))
        })
}
