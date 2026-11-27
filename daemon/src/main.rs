//! OhMyRASP host daemon.
//!
//! Wiring:
//!   spool file ──tail──▶ pipeline ──▶ in-memory store (console)
//!                                  └─▶ uploader ──▶ cloud control plane
//!                                                   (offline outbox + retry)
//!   console (axum) ◀── reads store / cloud status / control
//!   console ──writes──▶ control file ──polled──▶ Java agent

mod cli;
mod cloud;
mod config;
mod console;
#[cfg(test)]
mod contract_tests;
mod control;
mod model;
mod store;
mod tailer;
mod uploader;
mod util;

use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::cli::Cli;
use crate::cloud::CloudClient;
use crate::config::Config;
use crate::console::AppState;
use crate::control::Controller;
use crate::model::{AgentEvent, EventClass};
use crate::store::EventStore;
use crate::util::now_rfc3339;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse_args();
    let config = Config::load(&cli)?;
    init_tracing(&config.log.level);

    tracing::info!(version = VERSION, "starting ohmyrasp-daemon");

    // Shared state.
    let store = Arc::new(EventStore::new(config.store.capacity));
    let default_mode = config.control.mode()?;
    let controller = Arc::new(Controller::load_or_init(
        &config.control.path,
        default_mode,
    )?);
    // Log the effective mode: an existing control file wins over default_mode.
    tracing::info!(
        mode = controller.snapshot().mode.as_str(),
        default_mode = default_mode.as_str(),
        path = %config.control.path.display(),
        "control file loaded"
    );

    // Cloud uplink (optional). Standalone when not usable.
    let client = if config.cloud.usable() {
        Some(CloudClient::new(config.cloud.clone())?)
    } else {
        if config.cloud.enabled {
            tracing::warn!("cloud enabled but identity incomplete; running standalone");
        } else {
            tracing::info!("cloud uplink disabled; running standalone");
        }
        None
    };
    let (uploader, uploader_join) = uploader::spawn(
        config.cloud.clone(),
        config.buffer.clone(),
        client,
        Some(controller.clone()),
    );
    let cloud_status = uploader.status().clone();

    // Shutdown fan-out.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Ingest pipeline: tail the spool, record to the store, forward detections.
    let store_for_tail = store.clone();
    let mut next_seq: u64 = 1;
    let spool_cfg = config.spool.clone();
    let tail_shutdown = shutdown_rx.clone();
    let tailer_join = tokio::spawn(async move {
        tailer::run(spool_cfg, tail_shutdown, move |line| {
            if let Some(event) = AgentEvent::parse_line(next_seq, now_rfc3339(), line) {
                next_seq += 1;
                route(event, &store_for_tail, |event| uploader.offer(event));
            }
        })
        .await;
    });

    // Console HTTP server.
    let state = Arc::new(AppState {
        store: store.clone(),
        controller: controller.clone(),
        cloud_status,
        spool_path: config.spool.path.display().to_string(),
        control_path: config.control.path.display().to_string(),
        version: VERSION,
    });
    let app = console::router(state);
    let listener = TcpListener::bind(config.console.bind).await?;
    tracing::info!(
        "console ready at http://{}  (spool={}, control={})",
        config.console.bind,
        config.spool.path.display(),
        config.control.path.display(),
    );

    // Trigger shutdown on Ctrl-C / SIGTERM.
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received");
        let _ = shutdown_tx.send(true);
    });

    let mut server_shutdown = shutdown_rx.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            while !*server_shutdown.borrow_and_update() {
                if server_shutdown.changed().await.is_err() {
                    break;
                }
            }
        })
        .await?;

    // Server stopped: let the tailer finish (dropping the uploader feed), then
    // wait for the uploader to drain + persist its outbox.
    let _ = tailer_join.await;
    let _ = uploader_join.await;
    tracing::info!("ohmyrasp-daemon stopped");
    Ok(())
}

/// Send one parsed line where its class says: only a detection reaches the attack log, the
/// detection counters and `offer` (the uploader).
fn route(event: AgentEvent, store: &EventStore, offer: impl FnOnce(AgentEvent)) {
    match event.class() {
        EventClass::Detection => {
            store.record(&event);
            offer(event);
        }
        // Telemetry: latency panel only, never the attack log or the cloud.
        EventClass::Telemetry => store.record_latency(&event),
        // The start line: the agent entry of the status view only.
        EventClass::Lifecycle => store.record_lifecycle(&event),
        EventClass::Ignored => store.record_ignored(&event),
    }
}

fn init_tracing(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_of_an_unknown_kind_is_counted_and_never_uploaded() {
        let store = EventStore::new(10);
        let mut offered = 0;
        let line =
            r#"{"kind":"diagnostic","hook":"h","algorithm":"a","action":"block","confidence":99}"#;
        for seq in 1..=2 {
            let event = AgentEvent::parse_line(seq, "t".into(), line).unwrap();
            route(event, &store, |_| offered += 1);
        }
        let stats = store.stats();
        assert_eq!(offered, 0, "not offered to the uploader");
        assert_eq!((stats.total, stats.detections, stats.blocks), (0, 0, 0));
        assert_eq!(stats.retained, 0, "not in the attack log");
        assert_eq!(stats.ignored_kinds.len(), 1);
        assert_eq!(stats.ignored_kinds[0].key, "diagnostic");
        assert_eq!(stats.ignored_kinds[0].count, 2);
    }
}
