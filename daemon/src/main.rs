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
use crate::control::{Controller, Mode};
use crate::model::AgentEvent;
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
    let default_mode = Mode::parse(&config.control.default_mode).unwrap_or(Mode::Monitor);
    let controller = Arc::new(Controller::load_or_init(&config.control.path, default_mode)?);
    tracing::info!(mode = default_mode.as_str(), "control file initialised");

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
    let (uploader, uploader_join) =
        uploader::spawn(config.cloud.clone(), config.buffer.clone(), client);
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
                if event.is_detection() {
                    store_for_tail.record(&event);
                    uploader.offer(event);
                } else {
                    // Telemetry: latency panel only — never the attack log or the cloud.
                    store_for_tail.record_latency(&event);
                }
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
