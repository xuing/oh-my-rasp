//! In-memory event store for the console: a bounded ring of recent events plus
//! rolling counters and a latency reservoir for the "business impact" panel.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serde::Serialize;

use crate::model::AgentEvent;
use crate::util::now_rfc3339;

const LATENCY_SAMPLES: usize = 2000;

pub struct EventStore {
    capacity: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    events: VecDeque<AgentEvent>,
    total: u64,
    detections: u64,
    blocks: u64,
    telemetry: u64,
    by_hook: HashMap<String, u64>,
    by_algorithm: HashMap<String, u64>,
    by_action: HashMap<String, u64>,
    latencies: VecDeque<i64>,
    started_at: String,
    last_event_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencyStats {
    pub samples: usize,
    pub p50_us: i64,
    pub p95_us: i64,
    pub p99_us: i64,
    pub max_us: i64,
    pub avg_us: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Counter {
    pub key: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub total: u64,
    pub detections: u64,
    pub blocks: u64,
    pub telemetry: u64,
    pub retained: usize,
    pub started_at: String,
    pub last_event_at: Option<String>,
    pub latency: LatencyStats,
    pub by_hook: Vec<Counter>,
    pub by_algorithm: Vec<Counter>,
    pub by_action: Vec<Counter>,
}

impl EventStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner {
                events: VecDeque::new(),
                total: 0,
                detections: 0,
                blocks: 0,
                telemetry: 0,
                by_hook: HashMap::new(),
                by_algorithm: HashMap::new(),
                by_action: HashMap::new(),
                latencies: VecDeque::new(),
                started_at: now_rfc3339(),
                last_event_at: None,
            }),
        }
    }

    pub fn record(&self, event: &AgentEvent) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.total += 1;
        if event.is_detection() {
            inner.detections += 1;
        }
        if event.is_block() {
            inner.blocks += 1;
        }
        if !event.hook.is_empty() {
            *inner.by_hook.entry(event.hook.clone()).or_default() += 1;
        }
        if !event.algorithm.is_empty() {
            *inner.by_algorithm.entry(event.algorithm.clone()).or_default() += 1;
        }
        if !event.action.is_empty() {
            *inner.by_action.entry(event.action.clone()).or_default() += 1;
        }
        if let Some(latency) = event.latency_us {
            if latency >= 0 {
                inner.latencies.push_back(latency);
                while inner.latencies.len() > LATENCY_SAMPLES {
                    inner.latencies.pop_front();
                }
            }
        }
        inner.last_event_at = Some(event.received_at.clone());

        inner.events.push_back(event.clone());
        let capacity = self.capacity;
        while inner.events.len() > capacity {
            inner.events.pop_front();
        }
    }

    /// Record a telemetry-only latency sample: it feeds the business-latency
    /// panel but is not a detection, so it stays out of the attack log and the
    /// detection counters.
    pub fn record_latency(&self, event: &AgentEvent) {
        let Some(latency) = event.latency_us.filter(|v| *v >= 0) else { return };
        let mut inner = self.inner.lock().expect("store mutex");
        inner.telemetry += 1;
        inner.latencies.push_back(latency);
        while inner.latencies.len() > LATENCY_SAMPLES {
            inner.latencies.pop_front();
        }
    }

    /// Most-recent-first slice of retained events, optionally filtered.
    pub fn recent(&self, limit: usize, hook: Option<&str>, action: Option<&str>) -> Vec<AgentEvent> {
        let inner = self.inner.lock().expect("store mutex");
        inner
            .events
            .iter()
            .rev()
            .filter(|e| hook.is_none_or(|h| e.hook.contains(h)))
            .filter(|e| action.is_none_or(|a| e.action.eq_ignore_ascii_case(a)))
            .take(limit)
            .cloned()
            .collect()
    }

    pub fn stats(&self) -> StatsSnapshot {
        let inner = self.inner.lock().expect("store mutex");
        StatsSnapshot {
            total: inner.total,
            detections: inner.detections,
            blocks: inner.blocks,
            telemetry: inner.telemetry,
            retained: inner.events.len(),
            started_at: inner.started_at.clone(),
            last_event_at: inner.last_event_at.clone(),
            latency: latency_stats(&inner.latencies),
            by_hook: top_counters(&inner.by_hook, 20),
            by_algorithm: top_counters(&inner.by_algorithm, 20),
            by_action: top_counters(&inner.by_action, 20),
        }
    }
}

fn latency_stats(samples: &VecDeque<i64>) -> LatencyStats {
    if samples.is_empty() {
        return LatencyStats { samples: 0, p50_us: 0, p95_us: 0, p99_us: 0, max_us: 0, avg_us: 0 };
    }
    let mut sorted: Vec<i64> = samples.iter().copied().collect();
    sorted.sort_unstable();
    let sum: i64 = sorted.iter().sum();
    let n = sorted.len();
    LatencyStats {
        samples: n,
        p50_us: percentile(&sorted, 50.0),
        p95_us: percentile(&sorted, 95.0),
        p99_us: percentile(&sorted, 99.0),
        max_us: *sorted.last().unwrap(),
        avg_us: sum / n as i64,
    }
}

/// Nearest-rank percentile over a pre-sorted slice.
fn percentile(sorted: &[i64], pct: f64) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct / 100.0 * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

fn top_counters(map: &HashMap<String, u64>, limit: usize) -> Vec<Counter> {
    let mut counters: Vec<Counter> =
        map.iter().map(|(k, v)| Counter { key: k.clone(), count: *v }).collect();
    counters.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
    counters.truncate(limit);
    counters
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(seq: u64, hook: &str, action: &str, latency: Option<i64>) -> AgentEvent {
        AgentEvent {
            seq,
            received_at: "2026-06-06T00:00:00Z".into(),
            kind: "detection".into(),
            timestamp: String::new(),
            hook: hook.into(),
            algorithm: "alg".into(),
            action: action.into(),
            confidence: 80,
            message: String::new(),
            latency_us: latency,
            raw: json!({"hook": hook, "action": action}),
        }
    }

    #[test]
    fn ring_caps_and_counts() {
        let store = EventStore::new(2);
        store.record(&event(1, "a", "log", Some(10)));
        store.record(&event(2, "b", "block", Some(30)));
        store.record(&event(3, "c", "log", Some(50)));
        let stats = store.stats();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.blocks, 1);
        assert_eq!(stats.retained, 2); // capped
        assert_eq!(stats.latency.samples, 3);
        assert_eq!(stats.latency.max_us, 50);
        // most recent first
        let recent = store.recent(10, None, None);
        assert_eq!(recent[0].hook, "c");
    }

    #[test]
    fn telemetry_feeds_latency_only_not_attack_log() {
        let store = EventStore::new(10);
        store.record(&event(1, "sql", "block", Some(20)));
        let mut tel = event(2, "http_request", "observe", Some(80));
        tel.kind = "telemetry".into();
        store.record_latency(&tel);
        let stats = store.stats();
        assert_eq!(stats.detections, 1);
        assert_eq!(stats.telemetry, 1);
        assert_eq!(stats.retained, 1, "telemetry not added to the attack log");
        assert_eq!(stats.latency.samples, 2, "both latencies counted");
        assert_eq!(stats.latency.max_us, 80);
    }

    #[test]
    fn filters_by_hook_and_action() {
        let store = EventStore::new(10);
        store.record(&event(1, "ProcessBuilder.start", "block", None));
        store.record(&event(2, "sql", "log", None));
        assert_eq!(store.recent(10, Some("sql"), None).len(), 1);
        assert_eq!(store.recent(10, None, Some("block")).len(), 1);
    }
}
