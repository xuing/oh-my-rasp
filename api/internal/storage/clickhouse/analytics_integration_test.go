package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ohmyrasp/control-plane/internal/control"
	"github.com/ohmyrasp/control-plane/internal/storage/migrations"
)

func TestAnalyticsIntegrationClickHouseWorkflow(t *testing.T) {
	dsn := os.Getenv("OHMYRASP_CLICKHOUSE_TEST_DSN")
	if dsn == "" {
		t.Skip("set OHMYRASP_CLICKHOUSE_TEST_DSN to run clickhouse integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		t.Fatalf("open clickhouse: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping clickhouse: %v", err)
	}
	if err := migrations.Apply(ctx, db, migrations.ClickHouse); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	now := func() time.Time { return time.Date(2026, 5, 31, 13, 0, 0, 0, time.UTC) }
	analytics := NewAnalytics(db, now)
	suffix := time.Now().UnixNano()
	appID := fmt.Sprintf("app_ch_%d", suffix)
	envID := fmt.Sprintf("env_ch_%d", suffix)
	agentID := fmt.Sprintf("agt_ch_%d", suffix)
	policyID := fmt.Sprintf("pol_ch_%d", suffix)

	events := []control.SecurityEvent{
		{
			ID:            fmt.Sprintf("evt_attack_%d", suffix),
			Type:          "attack",
			ApplicationID: appID,
			EnvironmentID: envID,
			AgentID:       agentID,
			PolicyID:      policyID,
			PolicyVersion: 3,
			Hook:          "sql",
			Algorithm:     "sql_userinput",
			Severity:      "critical",
			Message:       "tautology detected",
			Attributes:    map[string]any{"path": "/checkout"},
			OccurredAt:    now(),
		},
		{
			ID:            fmt.Sprintf("evt_hook_%d", suffix),
			Type:          "hook",
			ApplicationID: appID,
			EnvironmentID: envID,
			AgentID:       agentID,
			PolicyID:      policyID,
			PolicyVersion: 3,
			Hook:          "command",
			Algorithm:     "command_userinput",
			Severity:      "medium",
			Message:       "command hook observed",
			Attributes: map[string]any{
				"class_name":  "java.lang.ProcessBuilder",
				"method_name": "start",
				"action":      "log",
				"latency_us":  731,
			},
			OccurredAt: now().Add(time.Second),
		},
		{
			ID:            fmt.Sprintf("evt_perf_%d", suffix),
			Type:          "performance",
			ApplicationID: appID,
			EnvironmentID: envID,
			AgentID:       agentID,
			PolicyID:      policyID,
			PolicyVersion: 3,
			Severity:      "low",
			Message:       "agent overhead sample",
			Attributes: map[string]any{
				"cpu_overhead_pct":      1.75,
				"memory_overhead_bytes": 524288,
				"hook_latency_p50_us":   55,
				"hook_latency_p95_us":   240,
				"rule_eval_p95_us":      120,
			},
			OccurredAt: now().Add(2 * time.Second),
		},
		{
			ID:            fmt.Sprintf("evt_crash_%d", suffix),
			Type:          "crash",
			ApplicationID: appID,
			EnvironmentID: envID,
			AgentID:       agentID,
			Severity:      "high",
			Message:       "agent crashed",
			Attributes: map[string]any{
				"runtime":       "java",
				"agent_version": "1.0.0",
				"error_class":   "NullPointerException",
				"stack_trace":   "stack",
			},
			OccurredAt: now().Add(3 * time.Second),
		},
	}
	for _, event := range events {
		if err := analytics.IngestEvent(ctx, event); err != nil {
			t.Fatalf("ingest %s: %v", event.Type, err)
		}
	}
	if err := analytics.IngestDependency(ctx, control.Dependency{
		ID:            fmt.Sprintf("dep_ch_%d", suffix),
		ApplicationID: appID,
		AgentID:       agentID,
		Name:          "spring-web",
		Version:       "6.2.0",
		Ecosystem:     "maven",
		PackagePath:   "org/springframework/spring-web/6.2.0/spring-web-6.2.0.jar",
		Licenses:      []string{"Apache-2.0"},
		Vulnerabilities: []control.DependencyVulnerability{{
			ID:             "CVE-2026-0001",
			Severity:       "critical",
			KnownExploited: true,
			FixedVersion:   "6.2.1",
		}},
		ObservedAt: now(),
	}, envID); err != nil {
		t.Fatalf("ingest dependency: %v", err)
	}
	if err := analytics.RecordRuleOverhead(ctx, RuleOverheadSample{
		BucketStart:      now(),
		ApplicationID:    appID,
		EnvironmentID:    envID,
		PolicyID:         policyID,
		PolicyVersion:    3,
		RuleID:           "rul_sql",
		Hook:             "sql",
		Executions:       1000,
		Blocked:          12,
		AverageLatencyUS: 42.5,
		P95LatencyUS:     180,
		MaxLatencyUS:     900,
	}); err != nil {
		t.Fatalf("record overhead: %v", err)
	}

	attacks, err := analytics.ListEvents(ctx, control.SecurityEventQuery{
		Type:          "attack",
		ApplicationID: appID,
		EnvironmentID: envID,
		AgentID:       agentID,
		PolicyID:      policyID,
		Severity:      "critical",
		Hook:          "sql",
		Limit:         1,
	})
	if err != nil {
		t.Fatalf("list attack events: %v", err)
	}
	if len(attacks) != 1 || attacks[0].ID != events[0].ID {
		t.Fatalf("expected filtered attack event %s in %#v", events[0].ID, attacks)
	}
	overview, err := analytics.EventOverview(ctx)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.EventCount < len(events) || overview.EventsByType["performance"] < 1 || overview.EventsBySeverity["critical"] < 1 {
		t.Fatalf("unexpected overview: %#v", overview)
	}
	assertTableHasID(t, ctx, db, "hook_events", events[1].ID)
	assertTableHasID(t, ctx, db, "performance_events", events[2].ID)
	assertTableHasID(t, ctx, db, "crash_events", events[3].ID)
	assertTableHasID(t, ctx, db, "dependency_observations", fmt.Sprintf("dep_ch_%d", suffix))
	assertDependencyObservationMetadata(t, ctx, db, fmt.Sprintf("dep_ch_%d", suffix))

	overhead, err := analytics.RuleOverhead(ctx, appID, policyID)
	if err != nil {
		t.Fatalf("rule overhead: %v", err)
	}
	if len(overhead) != 1 || overhead[0].RuleID != "rul_sql" || overhead[0].P95LatencyUS != 180 {
		t.Fatalf("unexpected overhead: %#v", overhead)
	}

	report, err := analytics.Observability(ctx, control.ObservabilityQuery{
		ApplicationID: appID,
		PolicyID:      policyID,
	})
	if err != nil {
		t.Fatalf("observability: %v", err)
	}
	if len(report.RuleOverhead) != 1 || report.RuleOverhead[0].RuleID != "rul_sql" {
		t.Fatalf("unexpected rule observability: %#v", report.RuleOverhead)
	}
	if len(report.HookLatency) != 1 || report.HookLatency[0].Hook != "command" || report.HookLatency[0].P95LatencyUS != 731 {
		t.Fatalf("unexpected hook observability: %#v", report.HookLatency)
	}
	if len(report.AgentOverhead) != 1 || report.AgentOverhead[0].AgentID != agentID || report.AgentOverhead[0].HookLatencyP95US != 240 {
		t.Fatalf("unexpected agent observability: %#v", report.AgentOverhead)
	}
	if len(report.PolicyPerformance) != 1 || report.PolicyPerformance[0].PolicyID != policyID || report.PolicyPerformance[0].RuleEvalP95US != 120 {
		t.Fatalf("unexpected policy observability: %#v", report.PolicyPerformance)
	}
}

func containsEvent(events []control.SecurityEvent, id string) bool {
	for _, event := range events {
		if event.ID == id {
			return true
		}
	}
	return false
}

func assertTableHasID(t *testing.T, ctx context.Context, db *sql.DB, table string, id string) {
	t.Helper()
	var count uint64
	if err := db.QueryRowContext(ctx, fmt.Sprintf("SELECT count() FROM %s WHERE id = ?", table), id).Scan(&count); err != nil {
		t.Fatalf("count %s id %s: %v", table, id, err)
	}
	if count == 0 {
		t.Fatalf("expected %s to contain id %s", table, id)
	}
}

func assertDependencyObservationMetadata(t *testing.T, ctx context.Context, db *sql.DB, id string) {
	t.Helper()
	var packagePath string
	var vulnerabilitiesJSON string
	if err := db.QueryRowContext(ctx, `
		SELECT package_path, vulnerabilities_json
		FROM dependency_observations
		WHERE id = ?
		ORDER BY ingested_at DESC
		LIMIT 1
	`, id).Scan(&packagePath, &vulnerabilitiesJSON); err != nil {
		t.Fatalf("dependency observation metadata %s: %v", id, err)
	}
	if packagePath == "" || !strings.Contains(vulnerabilitiesJSON, "critical") {
		t.Fatalf("expected dependency metadata in ClickHouse, got package_path=%q vulnerabilities=%q", packagePath, vulnerabilitiesJSON)
	}
}
