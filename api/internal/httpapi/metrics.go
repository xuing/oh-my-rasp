package httpapi

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

type metricsRecorder struct {
	mu                sync.Mutex
	policyPullBuckets []float64
	policyPullCount   map[string][]uint64
	policyPullSum     map[string]float64

	cacheMu      sync.Mutex
	cachedRender string
	cachedAt     time.Time
}

// eventOutboxBacklogCounter is implemented by stores that expose an
// undelivered-events count so /metrics can surface analytics delivery backlog.
type eventOutboxBacklogCounter interface {
	UndeliveredEventOutboxCount(ctx context.Context) (int, error)
}

func newMetricsRecorder() *metricsRecorder {
	buckets := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}
	return &metricsRecorder{
		policyPullBuckets: buckets,
		policyPullCount:   map[string][]uint64{"success": make([]uint64, len(buckets)+1), "error": make([]uint64, len(buckets)+1)},
		policyPullSum:     map[string]float64{"success": 0, "error": 0},
	}
}

func (m *metricsRecorder) observePolicyPull(duration time.Duration, err error) {
	status := "success"
	if err != nil {
		status = "error"
	}
	seconds := duration.Seconds()
	m.mu.Lock()
	defer m.mu.Unlock()
	counts, ok := m.policyPullCount[status]
	if !ok {
		counts = make([]uint64, len(m.policyPullBuckets)+1)
		m.policyPullCount[status] = counts
	}
	for i, upperBound := range m.policyPullBuckets {
		if seconds <= upperBound {
			counts[i]++
		}
	}
	counts[len(counts)-1]++
	m.policyPullSum[status] += seconds
}

// renderCached returns a rendered exposition, reusing a previous render while it
// is younger than ttl. A non-positive ttl disables caching. This bounds how often
// the expensive full-table store queries run under repeated scrapes.
func (m *metricsRecorder) renderCached(ctx context.Context, store control.Store, now func() time.Time, ttl time.Duration) string {
	if ttl <= 0 {
		return m.render(ctx, store, now)
	}
	current := now()
	m.cacheMu.Lock()
	if m.cachedRender != "" && current.Sub(m.cachedAt) < ttl {
		cached := m.cachedRender
		m.cacheMu.Unlock()
		return cached
	}
	m.cacheMu.Unlock()

	rendered := m.render(ctx, store, now)

	m.cacheMu.Lock()
	m.cachedRender = rendered
	m.cachedAt = current
	m.cacheMu.Unlock()
	return rendered
}

func (m *metricsRecorder) render(ctx context.Context, store control.Store, now func() time.Time) string {
	var b strings.Builder
	writeMetricHeader(&b, "ohmyrasp_api_up", "API process liveness", "gauge")
	writeMetric(&b, "ohmyrasp_api_up", nil, 1)

	scrapeTime := now()
	m.renderStoreMetrics(ctx, &b, store, scrapeTime)
	m.renderPolicyPullMetrics(&b)
	return b.String()
}

func (m *metricsRecorder) renderStoreMetrics(ctx context.Context, b *strings.Builder, store control.Store, scrapeTime time.Time) {
	writeMetricHeader(b, "ohmyrasp_metrics_scrape_error", "Whether a metrics scrape failed to collect a source from the control store", "gauge")
	scrapeErrors := map[string]float64{"agents": 0, "overview": 0, "events": 0, "observability": 0}

	agents, err := store.ListAgents(ctx)
	if err != nil {
		scrapeErrors["agents"] = 1
	} else {
		renderAgentMetrics(b, agents)
	}

	overview, err := store.Overview(ctx)
	if err != nil {
		scrapeErrors["overview"] = 1
	} else {
		renderOverviewMetrics(b, overview)
	}

	events, err := store.ListEvents(ctx, control.SecurityEventQuery{})
	if err != nil {
		scrapeErrors["events"] = 1
	} else {
		renderEventFreshnessMetrics(b, events, scrapeTime)
	}

	report, err := store.Observability(ctx, control.ObservabilityQuery{})
	if err != nil {
		scrapeErrors["observability"] = 1
	} else {
		renderObservabilityMetrics(b, report)
	}

	if counter, ok := store.(eventOutboxBacklogCounter); ok {
		writeMetricHeader(b, "ohmyrasp_event_outbox_undelivered", "Events awaiting delivery to ClickHouse analytics", "gauge")
		scrapeErrors["event_outbox"] = 0
		if backlog, err := counter.UndeliveredEventOutboxCount(ctx); err != nil {
			scrapeErrors["event_outbox"] = 1
		} else {
			writeMetric(b, "ohmyrasp_event_outbox_undelivered", nil, float64(backlog))
		}
	}

	for _, source := range sortedKeys(scrapeErrors) {
		writeMetric(b, "ohmyrasp_metrics_scrape_error", labels{"source": source}, scrapeErrors[source])
	}
}

func renderAgentMetrics(b *strings.Builder, agents []control.Agent) {
	writeMetricHeader(b, "ohmyrasp_agents_total", "Registered Agent count", "gauge")
	writeMetricHeader(b, "ohmyrasp_agents_online", "Registered Agents currently marked online", "gauge")
	writeMetricHeader(b, "ohmyrasp_agent_last_seen_timestamp_seconds", "Last Agent heartbeat timestamp", "gauge")

	online := 0
	for _, agent := range agents {
		if agent.Status == "online" {
			online++
		}
		writeMetric(b, "ohmyrasp_agent_last_seen_timestamp_seconds", labels{
			"agent_id":       agent.ID,
			"application_id": agent.ApplicationID,
			"environment_id": agent.EnvironmentID,
			"hostname":       agent.Hostname,
			"status":         agent.Status,
			"version":        agent.Version,
		}, float64(agent.LastSeenAt.Unix()))
	}
	writeMetric(b, "ohmyrasp_agents_total", nil, float64(len(agents)))
	writeMetric(b, "ohmyrasp_agents_online", nil, float64(online))
}

func renderOverviewMetrics(b *strings.Builder, overview control.Overview) {
	writeMetricHeader(b, "ohmyrasp_applications_total", "Application count", "gauge")
	writeMetricHeader(b, "ohmyrasp_events_total", "Security events accepted by type and severity", "counter")
	writeMetric(b, "ohmyrasp_applications_total", nil, float64(overview.ApplicationCount))
	for _, eventType := range sortedKeys(overview.EventsByType) {
		writeMetric(b, "ohmyrasp_events_total", labels{"type": eventType, "severity": ""}, float64(overview.EventsByType[eventType]))
	}
	for _, severity := range sortedKeys(overview.EventsBySeverity) {
		writeMetric(b, "ohmyrasp_events_total", labels{"type": "", "severity": severity}, float64(overview.EventsBySeverity[severity]))
	}
}

func renderEventFreshnessMetrics(b *strings.Builder, events []control.SecurityEvent, scrapeTime time.Time) {
	writeMetricHeader(b, "ohmyrasp_last_event_ingested_timestamp_seconds", "Timestamp of the newest accepted event by type", "gauge")
	writeMetricHeader(b, "ohmyrasp_event_ingest_lag_seconds", "Age of the newest accepted event by type", "gauge")
	latestByType := map[string]time.Time{}
	for _, event := range events {
		if event.Type == "" || event.OccurredAt.IsZero() {
			continue
		}
		if latestByType[event.Type].Before(event.OccurredAt) {
			latestByType[event.Type] = event.OccurredAt
		}
	}
	for _, eventType := range sortedTimeKeys(latestByType) {
		latest := latestByType[eventType]
		lag := scrapeTime.Sub(latest)
		if lag < 0 {
			lag = 0
		}
		writeMetric(b, "ohmyrasp_last_event_ingested_timestamp_seconds", labels{"type": eventType}, float64(latest.Unix()))
		writeMetric(b, "ohmyrasp_event_ingest_lag_seconds", labels{"type": eventType}, lag.Seconds())
	}
}

func renderObservabilityMetrics(b *strings.Builder, report control.ObservabilityReport) {
	writeMetricHeader(b, "ohmyrasp_hook_latency_p95_seconds", "Hook latency p95 by hook", "gauge")
	writeMetricHeader(b, "ohmyrasp_rule_eval_latency_p95_seconds", "Policy rule evaluation latency p95 by policy version", "gauge")
	writeMetricHeader(b, "ohmyrasp_agent_cpu_overhead_percent", "Agent CPU overhead percent", "gauge")
	for _, item := range report.HookLatency {
		writeMetric(b, "ohmyrasp_hook_latency_p95_seconds", labels{"hook": item.Hook}, microsecondsToSeconds(item.P95LatencyUS))
	}
	for _, item := range report.PolicyPerformance {
		writeMetric(b, "ohmyrasp_rule_eval_latency_p95_seconds", labels{
			"policy_id":      item.PolicyID,
			"policy_version": strconv.Itoa(item.PolicyVersion),
		}, microsecondsToSeconds(item.RuleEvalP95US))
	}
	for _, item := range report.AgentOverhead {
		writeMetric(b, "ohmyrasp_agent_cpu_overhead_percent", labels{"agent_id": item.AgentID}, item.CPUOverheadPCT)
	}
}

func (m *metricsRecorder) renderPolicyPullMetrics(b *strings.Builder) {
	writeMetricHeader(b, "ohmyrasp_policy_pull_latency_seconds", "Agent policy pull latency", "histogram")
	m.mu.Lock()
	defer m.mu.Unlock()
	statuses := sortedHistogramStatuses(m.policyPullCount)
	for _, status := range statuses {
		counts := m.policyPullCount[status]
		for i, upperBound := range m.policyPullBuckets {
			writeMetric(b, "ohmyrasp_policy_pull_latency_seconds_bucket", labels{
				"status": status,
				"le":     strconv.FormatFloat(upperBound, 'f', -1, 64),
			}, float64(counts[i]))
		}
		writeMetric(b, "ohmyrasp_policy_pull_latency_seconds_bucket", labels{"status": status, "le": "+Inf"}, float64(counts[len(counts)-1]))
		writeMetric(b, "ohmyrasp_policy_pull_latency_seconds_sum", labels{"status": status}, m.policyPullSum[status])
		writeMetric(b, "ohmyrasp_policy_pull_latency_seconds_count", labels{"status": status}, float64(counts[len(counts)-1]))
	}
}

type labels map[string]string

func writeMetricHeader(b *strings.Builder, name string, help string, metricType string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func writeMetric(b *strings.Builder, name string, metricLabels labels, value float64) {
	b.WriteString(name)
	if len(metricLabels) > 0 {
		b.WriteByte('{')
		keys := sortedKeys(metricLabels)
		for i, key := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(b, `%s="%s"`, key, escapePrometheusLabelValue(metricLabels[key]))
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(value, 'f', -1, 64))
	b.WriteByte('\n')
}

func escapePrometheusLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func microsecondsToSeconds(value int) float64 {
	return float64(value) / 1_000_000
}

func sortedKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedTimeKeys(items map[string]time.Time) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedHistogramStatuses(items map[string][]uint64) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
