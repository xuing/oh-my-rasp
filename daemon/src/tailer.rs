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
    let mut leftover: Vec<u8> = Vec::new();

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
//
// TODO(durability): the read offset is not persisted across restarts. Without
// `--from-start` a restart resumes at the current EOF, so any events the agent
// appended while the daemon was down are skipped; with `--from-start` the whole
// spool is re-ingested and already-forwarded events are duplicated. A durable
// fix would checkpoint the byte offset (e.g. to `buffer/spool.cursor`) and
// resume from it. Left out here because it needs its own crash-consistency
// tests; see the "offset-persistence" finding.
async fn initial_offset(path: &Path, from_start: bool) -> u64 {
    if from_start {
        return 0;
    }
    tokio::fs::metadata(path)
        .await
        .map(|m| m.len())
        .unwrap_or(0)
}

async fn poll_once<F>(
    path: &Path,
    mut offset: u64,
    leftover: &mut Vec<u8>,
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

    leftover.extend_from_slice(&buf);
    // Emit every complete line; retain the trailing partial line for next poll.
    // Split on raw bytes BEFORE utf-8 conversion so a multibyte character that
    // straddles two reads is reassembled instead of mangled.
    while let Some(idx) = leftover.iter().position(|&b| b == b'\n') {
        let line: Vec<u8> = leftover.drain(..=idx).collect();
        let text = String::from_utf8_lossy(&line);
        on_line(text.trim_end_matches(['\n', '\r']));
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

        let cfg = SpoolConfig {
            path: path.clone(),
            poll_interval_ms: 20,
            from_start: true,
        };
        let (tx, rx) = watch::channel(false);
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = seen.clone();

        let handle = tokio::spawn(async move {
            run(cfg, rx, move |line| {
                sink.lock().unwrap().push(line.to_string())
            })
            .await;
        });

        // Append more lines after the tailer has started.
        tokio::time::sleep(Duration::from_millis(60)).await;
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(b"{\"b\":2}\n{\"c\":3}\n").unwrap();
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
        tx.send(true).unwrap();
        handle.await.unwrap();

        let lines = seen.lock().unwrap().clone();
        assert_eq!(lines, vec!["{\"a\":1}", "{\"b\":2}", "{\"c\":3}"]);
    }

    #[tokio::test]
    async fn reassembles_multibyte_char_split_across_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        // "查" is e6 9f a5 in UTF-8; write the line in two appends that split it.
        let full = "{\"uri\":\"/查询\"}".as_bytes();
        let split = full.len() - 4; // inside the final multibyte sequence
        std::fs::write(&path, &full[..split]).unwrap();

        let cfg = SpoolConfig {
            path: path.clone(),
            poll_interval_ms: 20,
            from_start: true,
        };
        let (tx, rx) = watch::channel(false);
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = seen.clone();
        let handle = tokio::spawn(async move {
            run(cfg, rx, move |line| {
                sink.lock().unwrap().push(line.to_string())
            })
            .await;
        });

        // Let the tailer consume the partial bytes, then complete the line.
        tokio::time::sleep(Duration::from_millis(80)).await;
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(&full[split..]).unwrap();
            f.write_all(b"\n").unwrap();
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
        tx.send(true).unwrap();
        handle.await.unwrap();

        let lines = seen.lock().unwrap().clone();
        assert_eq!(lines, vec!["{\"uri\":\"/查询\"}"]);
    }

    #[tokio::test]
    async fn poll_once_resets_offset_on_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, b"{\"a\":1}\n{\"b\":2}\n").unwrap();

        let mut leftover = Vec::new();
        let mut seen = Vec::<String>::new();
        let offset = {
            let mut push = |l: &str| seen.push(l.to_string());
            poll_once(&path, 0, &mut leftover, &mut push).await.unwrap()
        };
        assert_eq!(seen, vec!["{\"a\":1}", "{\"b\":2}"]);
        assert_eq!(offset, 16);

        // Rotate: replace with a shorter file so len < offset triggers a reset.
        std::fs::write(&path, b"{\"c\":3}\n").unwrap();
        seen.clear();
        let new_offset = {
            let mut push = |l: &str| seen.push(l.to_string());
            poll_once(&path, offset, &mut leftover, &mut push)
                .await
                .unwrap()
        };
        assert_eq!(
            seen,
            vec!["{\"c\":3}"],
            "reads the rotated file from the top"
        );
        assert_eq!(new_offset, 8, "offset tracks the shorter file");
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn poll_once_drops_oversized_partial_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        // More than the guard, with no newline: an unterminated line the tailer
        // must refuse to buffer unboundedly.
        let big = vec![b'a'; MAX_LEFTOVER + 16];
        std::fs::write(&path, &big).unwrap();

        let mut leftover = Vec::new();
        let mut count = 0usize;
        let offset = {
            let mut bump = |_l: &str| count += 1;
            poll_once(&path, 0, &mut leftover, &mut bump).await.unwrap()
        };
        assert_eq!(count, 0, "no complete line was emitted");
        assert!(leftover.is_empty(), "oversized partial line was dropped");
        assert_eq!(offset, big.len() as u64);
    }
}
