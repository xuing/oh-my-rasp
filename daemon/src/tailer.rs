//! Spool tailer.
//!
//! Follows the agent's NDJSON event file by polling. Polling (rather than inotify
//! / `notify`) is deliberate: it sidesteps platform-specific watch quirks, and
//! the only cost is up to one poll interval of latency — irrelevant for a local
//! log follower. Handles late file creation, appends across partial lines, and
//! truncation/rotation (detected when the file shrinks below the read offset).

use std::io::SeekFrom;
use std::path::Path;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::watch;
use tokio::time::{Duration, sleep};

use crate::config::SpoolConfig;

const MAX_LEFTOVER: usize = 1 << 20; // 1 MiB guard against an unterminated line

/// Tail `cfg.path`, invoking `on_line` for each complete line. Returns when the
/// `shutdown` signal flips to `true`.
pub async fn run<F>(cfg: SpoolConfig, mut shutdown: watch::Receiver<bool>, mut on_line: F)
where
    F: FnMut(&str),
{
    let path = cfg.path.clone();
    let poll = Duration::from_millis(cfg.poll_interval_ms.max(20));
    let mut offset: u64 = initial_offset(&path, cfg.from_start).await;
    let mut leftover = String::new();

    tracing::info!(path = %path.display(), offset, "tailing agent spool");

    loop {
        if *shutdown.borrow() {
            break;
        }
        match poll_once(&path, offset, &mut leftover, &mut on_line).await {
            Ok(new_offset) => offset = new_offset,
            Err(err) => tracing::debug!(%err, "spool poll error (will retry)"),
        }
        tokio::select! {
            _ = sleep(poll) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
    tracing::info!("spool tailer stopped");
}

/// Where to begin reading: 0 to replay everything, or current EOF to follow only
/// new events.
async fn initial_offset(path: &Path, from_start: bool) -> u64 {
    if from_start {
        return 0;
    }
    tokio::fs::metadata(path).await.map(|m| m.len()).unwrap_or(0)
}

async fn poll_once<F>(
    path: &Path,
    mut offset: u64,
    leftover: &mut String,
    on_line: &mut F,
) -> std::io::Result<u64>
where
    F: FnMut(&str),
{
    let Ok(meta) = tokio::fs::metadata(path).await else {
        // File not present yet; keep waiting.
        return Ok(offset);
    };
    let len = meta.len();
    if len < offset {
        // Truncated or rotated: start over from the top of the new file.
        tracing::info!(path = %path.display(), "spool truncated/rotated; resetting offset");
        offset = 0;
        leftover.clear();
    }
    if len == offset {
        return Ok(offset);
    }

    let mut file = File::open(path).await?;
    file.seek(SeekFrom::Start(offset)).await?;
    let mut buf = Vec::with_capacity((len - offset) as usize);
    file.take(len - offset).read_to_end(&mut buf).await?;

    leftover.push_str(&String::from_utf8_lossy(&buf));
    // Emit every complete line; retain the trailing partial line for next poll.
    while let Some(idx) = leftover.find('\n') {
        let line: String = leftover.drain(..=idx).collect();
        on_line(line.trim_end_matches(['\n', '\r']));
    }
    if leftover.len() > MAX_LEFTOVER {
        tracing::warn!("dropping oversized partial spool line");
        leftover.clear();
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn tails_appended_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, b"{\"a\":1}\n").unwrap();

        let cfg = SpoolConfig { path: path.clone(), poll_interval_ms: 20, from_start: true };
        let (tx, rx) = watch::channel(false);
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = seen.clone();

        let handle = tokio::spawn(async move {
            run(cfg, rx, move |line| sink.lock().unwrap().push(line.to_string())).await;
        });

        // Append more lines after the tailer has started.
        tokio::time::sleep(Duration::from_millis(60)).await;
        {
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"b\":2}\n{\"c\":3}\n").unwrap();
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
        tx.send(true).unwrap();
        handle.await.unwrap();

        let lines = seen.lock().unwrap().clone();
        assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}", "{\"c\":3}"]);
    }
}
