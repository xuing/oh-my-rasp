//! Command-line interface.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

/// OhMyRASP host daemon — ingests Java-agent events, forwards them to the
/// cloud control plane, and serves a local single-host console.
#[derive(Debug, Parser)]
#[command(name = "ohmyrasp-daemon", version, about, long_about = None)]
pub struct Cli {
    /// Path to a TOML config file (defaults to ./ohmyrasp-daemon.toml if present).
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Override the agent event spool file to tail.
    #[arg(long, value_name = "FILE")]
    pub spool: Option<PathBuf>,

    /// Override the control file the daemon writes for the agent to poll.
    #[arg(long, value_name = "FILE")]
    pub control: Option<PathBuf>,

    /// Override the console bind address (e.g. 127.0.0.1:7070).
    #[arg(long, value_name = "ADDR")]
    pub console_bind: Option<SocketAddr>,

    /// Cloud control-plane base URL; implies --cloud.
    #[arg(long, value_name = "URL")]
    pub backend_url: Option<String>,

    /// Enable the cloud uplink (requires app_id/app_secret/environment_id).
    #[arg(long)]
    pub cloud: bool,

    /// Replay the entire existing spool file on startup instead of tailing
    /// from the current end-of-file.
    #[arg(long)]
    pub from_start: bool,
}

impl Cli {
    pub fn parse_args() -> Self {
        Cli::parse()
    }
}
