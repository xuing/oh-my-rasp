//! In-memory event store for the console: a bounded ring of recent events plus
//! rolling counters and a latency reservoir for the "business impact" panel.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serde::Serialize;

use crate::model::{AgentEvent, AgentInfo, HookMiss};
use crate::util::now_rfc3339;

const LATENCY_SAMPLES: usize = 2000;
/// The most distinct labels `ignored_kinds` keeps; a line of any further kind is counted under
/// [`OTHER_IGNORED`]. A spool producer that writes a new kind on every line cannot grow the map.
const MAX_IGNORED_LABELS: usize = 32;
/// The longest a label is, in characters, before it is used.
const MAX_IGNORED_LABEL_CHARS: usize = 64;
/// Where the kinds past [`MAX_IGNORED_LABELS`] are counted.
pub const OTHER_IGNORED: &str = "(other)";
/// The most distinct hook misses `hook_misses` keeps, each by its unit, class and the identity of the
/// code it came from (file name, path and `Implementation-Version`). A line for a further new miss
/// is only counted in `hook_misses_dropped`, a count of lines, so many JVMs, each reporting its own
/// set, cannot grow the list.
const MAX_HOOK_MISSES: usize = 64;

/// What the store did with one diagnostic line, for the caller that logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticOutcome {
    /// A hook miss no earlier line named: it is now in `hook_misses`.
    NewHookMiss,
    /// The first line saying that an agent stopped reporting further misses: it set
    /// `hook_misses_suppressed`.
    FirstSuppression,
    /// Anything else: a repeat, a miss past the bound, a later suppression line, another diagnostic.
    Counted,
}

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
    ignored_kinds: HashMap<String, u64>,
    diagnostics: u64,
    hook_misses: Vec<HookMissEntry>,
    hook_misses_dropped: u64,
    hook_misses_suppressed: bool,
    agent: Option<AgentInfo>,
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

/// A hook that did not apply, as the status view keeps it: what the agent reported, when the
/// daemon first read it and how many lines named the same unit, class and code (file name, path and
/// version).
#[derive(Debug, Clone, Serialize)]
pub struct HookMissEntry {
    #[serde(flatten)]
    pub miss: HookMiss,
    /// When the daemon first read a line for this pair.
    pub first_seen: String,
    /// How many lines named this miss (the agents write one per JVM; several JVMs add up).
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
    /// Lines of a `kind` the daemon does not know, by kind (or by `event:<event>` when the line
    /// has no kind). Never counted as detections and never uploaded.
    pub ignored_kinds: Vec<Counter>,
    /// Diagnostic lines of any kind (hook misses and the suppressed line), in total. Never counted
    /// as detections and never uploaded.
    pub diagnostics: u64,
    /// The hooks that did not apply, one entry per distinct (unit, class, code source), at most
    /// 64 of them, in the order first read.
    pub hook_misses: Vec<HookMissEntry>,
    /// Distinct pairs not kept in `hook_misses` because it was full.
    pub hook_misses_dropped: u64,
    /// True once an agent said it stopped writing hook-miss lines for the rest of its JVM's life,
    /// so the list may be incomplete.
    pub hook_misses_suppressed: bool,
    /// The agent as its last start line described it; absent until one was read.
    pub agent: Option<AgentInfo>,
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
                ignored_kinds: HashMap::new(),
                diagnostics: 0,
                hook_misses: Vec::new(),
                hook_misses_dropped: 0,
                hook_misses_suppressed: false,
                agent: None,
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
            *inner
                .by_algorithm
                .entry(event.algorithm.clone())
                .or_default() += 1;
        }
        if !event.action.is_empty() {
            *inner.by_action.entry(event.action.clone()).or_default() += 1;
        }
        if let Some(latency) = event.latency_us
            && latency >= 0
        {
            inner.latencies.push_back(latency);
            while inner.latencies.len() > LATENCY_SAMPLES {
                inner.latencies.pop_front();
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
        let Some(latency) = event.latency_us.filter(|v| *v >= 0) else {
            return;
        };
        let mut inner = self.inner.lock().expect("store mutex");
        inner.telemetry += 1;
        inner.latencies.push_back(latency);
        while inner.latencies.len() > LATENCY_SAMPLES {
            inner.latencies.pop_front();
        }
    }

    /// Record an agent lifecycle (start) line: it updates the agent entry of the status view and
    /// is otherwise invisible. It is not a detection, so it counts nowhere else.
    pub fn record_lifecycle(&self, event: &AgentEvent) {
        let mut inner = self.inner.lock().expect("store mutex");
        inner.agent = Some(event.agent_info());
    }

    /// Count a line of a kind the daemon does not know. It is not retained, not counted as a
    /// detection and not uploaded.
    pub fn record_ignored(&self, event: &AgentEvent) {
        let label = truncated_label(event.ignored_label());
        tracing::debug!(%label, "ignoring an agent line of an unknown kind");
        let mut inner = self.inner.lock().expect("store mutex");
        let known = inner.ignored_kinds.contains_key(&label);
        let key = if known || inner.ignored_kinds.len() < MAX_IGNORED_LABELS {
            label
        } else {
            OTHER_IGNORED.to_string()
        };
        *inner.ignored_kinds.entry(key).or_default() += 1;
    }

    /// Count an agent diagnostic line. It is not retained in the attack log, not counted as a
    /// detection and not uploaded. A hook miss is kept per unit, class and code identity (file name,
    /// path and version, so two JARs of one file name, or two versions, are two entries) and the
    /// outcome says when that miss is new and kept, so the caller logs it once; the first line that
    /// says further misses are suppressed sets `hook_misses_suppressed` and says so, so the caller
    /// warns once. Any other diagnostic is only counted in the total.
    pub fn record_diagnostic(&self, event: &AgentEvent) -> DiagnosticOutcome {
        let miss = event.hook_miss();
        let mut inner = self.inner.lock().expect("store mutex");
        inner.diagnostics += 1;
        if event.is_hook_miss_suppressed() {
            let first = !inner.hook_misses_suppressed;
            inner.hook_misses_suppressed = true;
            return if first {
                DiagnosticOutcome::FirstSuppression
            } else {
                DiagnosticOutcome::Counted
            };
        }
        let Some(miss) = miss else {
            return DiagnosticOutcome::Counted;
        };
        let same = |kept: &HookMissEntry| {
            kept.miss.unit == miss.unit
                && kept.miss.class == miss.class
                && kept.miss.code_source == miss.code_source
                && kept.miss.code_source_path == miss.code_source_path
                && kept.miss.implementation_version == miss.implementation_version
        };
        if let Some(kept) = inner.hook_misses.iter_mut().find(|kept| same(kept)) {
            kept.count += 1;
            return DiagnosticOutcome::Counted;
        }
        if inner.hook_misses.len() >= MAX_HOOK_MISSES {
            inner.hook_misses_dropped += 1;
            tracing::debug!(unit = ?miss.unit, class = ?miss.class, "hook-miss list full; counting only");
            return DiagnosticOutcome::Counted;
        }
        inner.hook_misses.push(HookMissEntry {
            miss,
            first_seen: event.received_at.clone(),
            count: 1,
        });
        DiagnosticOutcome::NewHookMiss
    }

    /// Most-recent-first slice of retained events, optionally filtered.
    pub fn recent(
        &self,
        limit: usize,
        hook: Option<&str>,
        action: Option<&str>,
    ) -> Vec<AgentEvent> {
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
            ignored_kinds: top_counters(&inner.ignored_kinds, 20),
            diagnostics: inner.diagnostics,
            hook_misses: inner.hook_misses.clone(),
            hook_misses_dropped: inner.hook_misses_dropped,
            hook_misses_suppressed: inner.hook_misses_suppressed,
            agent: inner.agent.clone(),
        }
    }
}

/// The label cut to [`MAX_IGNORED_LABEL_CHARS`] characters.
fn truncated_label(label: String) -> String {
    match label.char_indices().nth(MAX_IGNORED_LABEL_CHARS) {
        Some((end, _)) => label[..end].to_string(),
        None => label,
    }
}

fn latency_stats(samples: &VecDeque<i64>) -> LatencyStats {
    if samples.is_empty() {
        return LatencyStats {
            samples: 0,
            p50_us: 0,
            p95_us: 0,
            p99_us: 0,
            max_us: 0,
            avg_us: 0,
        };
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
    let mut counters: Vec<Counter> = map
        .iter()
        .map(|(k, v)| Counter {
            key: k.clone(),
            count: *v,
        })
        .collect();
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

    fn ignored(seq: u64, kind: &str) -> AgentEvent {
        AgentEvent {
            kind: kind.into(),
            ..event(seq, "h", "log", None)
        }
    }

    /// A spool producer that writes a new kind on every line cannot grow the map: past the
    /// limit the kinds are counted under `(other)`, and nothing is lost from the total.
    #[test]
    fn the_ignored_kinds_are_bounded_however_many_distinct_kinds_arrive() {
        let store = EventStore::new(10);
        for seq in 0..10_000u64 {
            store.record_ignored(&ignored(seq, &format!("kind-{seq}")));
        }
        {
            let inner = store.inner.lock().unwrap();
            assert!(
                inner.ignored_kinds.len() <= MAX_IGNORED_LABELS + 1,
                "{} labels",
                inner.ignored_kinds.len()
            );
            assert_eq!(inner.ignored_kinds.values().sum::<u64>(), 10_000);
            assert_eq!(
                inner.ignored_kinds[OTHER_IGNORED],
                10_000 - MAX_IGNORED_LABELS as u64
            );
        }
        // A kind that already has a label keeps counting under it.
        store.record_ignored(&ignored(0, "kind-0"));
        let stats = store.stats();
        let kind0 = stats.ignored_kinds.iter().find(|c| c.key == "kind-0");
        assert_eq!(kind0.map(|c| c.count), Some(2));
    }

    fn hook_miss_event(seq: u64, unit: &str, class: &str, code_source: Option<&str>) -> AgentEvent {
        let raw = json!({
            "kind": "diagnostic", "diagnostic": "hook_miss", "unit": unit, "class": class,
            "reason": "no_agent_call", "code_source": code_source,
        });
        AgentEvent::parse_line(seq, format!("t{seq}"), &raw.to_string()).unwrap()
    }

    /// A miss that names the code it came from by file name, path and version.
    fn located_miss_event(seq: u64, path: &str, version: Option<&str>) -> AgentEvent {
        let raw = json!({
            "kind": "diagnostic", "diagnostic": "hook_miss", "unit": "U", "class": "a.C",
            "reason": "no_agent_call", "code_source": "x.jar", "code_source_path": path,
            "implementation_version": version,
        });
        AgentEvent::parse_line(seq, format!("t{seq}"), &raw.to_string()).unwrap()
    }

    fn is_new(outcome: DiagnosticOutcome) -> bool {
        outcome == DiagnosticOutcome::NewHookMiss
    }

    /// Many JVMs, each reporting its own classes, cannot grow the list: past the limit a new pair
    /// is only counted, and a pair already kept keeps counting.
    #[test]
    fn the_hook_misses_are_bounded_however_many_distinct_pairs_arrive() {
        let store = EventStore::new(10);
        for seq in 0..10_000u64 {
            let new = store.record_diagnostic(&hook_miss_event(
                seq,
                "U",
                &format!("a.C{seq}"),
                Some("x.jar"),
            ));
            assert_eq!(is_new(new), seq < MAX_HOOK_MISSES as u64, "pair {seq}");
        }
        assert!(!is_new(store.record_diagnostic(&hook_miss_event(
            0,
            "U",
            "a.C0",
            Some("x.jar")
        ))));
        let stats = store.stats();
        assert_eq!(stats.hook_misses.len(), MAX_HOOK_MISSES);
        assert_eq!(
            stats.hook_misses_dropped,
            10_000 - MAX_HOOK_MISSES as u64,
            "a count of lines, not of distinct misses"
        );
        assert_eq!(stats.diagnostics, 10_001);
        assert_eq!(stats.hook_misses[0].count, 2, "a kept pair keeps counting");
        assert_eq!(stats.hook_misses[0].first_seen, "t0");
        assert!(!stats.hook_misses_suppressed);
        // None of it is a detection or an ignored kind.
        assert_eq!((stats.total, stats.detections, stats.retained), (0, 0, 0));
        assert!(stats.ignored_kinds.is_empty());
    }

    #[test]
    fn a_hook_miss_is_one_entry_per_unit_class_and_code_source() {
        let store = EventStore::new(10);
        assert!(is_new(store.record_diagnostic(&hook_miss_event(
            1,
            "U",
            "a.C",
            Some("x-1.jar")
        ))));
        assert!(!is_new(store.record_diagnostic(&hook_miss_event(
            2,
            "U",
            "a.C",
            Some("x-1.jar")
        ))));
        assert!(is_new(store.record_diagnostic(&hook_miss_event(
            3,
            "U",
            "a.C",
            Some("x-2.jar")
        ))));
        assert!(is_new(
            store.record_diagnostic(&hook_miss_event(4, "U", "a.C", None))
        ));
        assert!(is_new(store.record_diagnostic(&hook_miss_event(
            5,
            "V",
            "a.C",
            Some("x-1.jar")
        ))));
        let stats = store.stats();
        let counts: Vec<u64> = stats.hook_misses.iter().map(|m| m.count).collect();
        assert_eq!(counts, [2, 1, 1, 1]);
        assert_eq!(stats.diagnostics, 5);
        // The members of the entry are serialised flat, next to `first_seen` and `count`.
        let first = serde_json::to_value(&stats.hook_misses[0]).unwrap();
        assert_eq!(first["unit"], "U");
        assert_eq!(first["format"], "primary");
        assert_eq!(first["first_seen"], "t1");
        assert_eq!(first["count"], 2);
    }

    /// Two JARs of one file name, in different places or of different versions, are two misses: the
    /// file name alone does not say which library the line is about.
    #[test]
    fn jars_of_one_file_name_are_told_apart_by_path_and_version() {
        let store = EventStore::new(10);
        assert!(is_new(store.record_diagnostic(&located_miss_event(
            1,
            "/a/x.jar",
            Some("1.0")
        ))));
        assert!(!is_new(store.record_diagnostic(&located_miss_event(
            2,
            "/a/x.jar",
            Some("1.0")
        ))));
        assert!(
            is_new(store.record_diagnostic(&located_miss_event(3, "/b/x.jar", Some("1.0")))),
            "another path"
        );
        assert!(
            is_new(store.record_diagnostic(&located_miss_event(4, "/a/x.jar", Some("2.0")))),
            "another version"
        );
        assert!(
            is_new(store.record_diagnostic(&located_miss_event(5, "/a/x.jar", None))),
            "no version"
        );
        let counts: Vec<u64> = store.stats().hook_misses.iter().map(|m| m.count).collect();
        assert_eq!(counts, [2, 1, 1, 1]);
    }

    #[test]
    fn the_suppressed_line_sets_the_flag_and_is_otherwise_only_counted() {
        let store = EventStore::new(10);
        let line = r#"{"event":"ohmyrasp-hook-miss-suppressed","limit":32}"#;
        let event = AgentEvent::parse_line(1, "t".into(), line).unwrap();
        assert_eq!(
            store.record_diagnostic(&event),
            DiagnosticOutcome::FirstSuppression
        );
        let stats = store.stats();
        assert!(stats.hook_misses_suppressed);
        assert_eq!((stats.diagnostics, stats.hook_misses.len()), (1, 0));
        // A JVM after the first says it again: counted, and the transition has happened.
        assert_eq!(store.record_diagnostic(&event), DiagnosticOutcome::Counted);
        assert_eq!(store.stats().diagnostics, 2);
    }

    #[test]
    fn an_ignored_label_is_cut_to_64_characters_before_it_is_used() {
        let store = EventStore::new(10);
        store.record_ignored(&ignored(1, &"k".repeat(10_000)));
        // Multi-byte characters are cut on a character boundary.
        store.record_ignored(&ignored(2, &"\u{e9}".repeat(100)));
        let stats = store.stats();
        let keys: Vec<&str> = stats.ignored_kinds.iter().map(|c| c.key.as_str()).collect();
        assert!(keys.contains(&"k".repeat(64).as_str()), "{keys:?}");
        assert!(keys.contains(&"\u{e9}".repeat(64).as_str()), "{keys:?}");
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
