package clickhouse

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohmyrasp/control-plane/internal/control"
)

type Analytics struct {
	db  *sql.DB
	now func() time.Time
}

func NewAnalytics(db *sql.DB, now func() time.Time) *Analytics {
	if now == nil {
		now = time.Now
	}
	return &Analytics{db: db, now: now}
}

func (a *Analytics) IngestEvent(ctx context.Context, event control.SecurityEvent) error {
	if event.ID == "" {
		event.ID = control.NewID("evt")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = a.now().UTC()
	}
	attributes, err := marshalAttributes(event.Attributes)
	if err != nil {
		return err
	}
	if _, err := a.db.ExecContext(ctx, `
		INSERT INTO security_events (
			id, type, application_id, environment_id, agent_id, policy_id, policy_version,
			hook, algorithm, severity, message, attributes_json, occurred_at, ingested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.Type, event.ApplicationID, event.EnvironmentID, event.AgentID, event.PolicyID, event.PolicyVersion, event.Hook, event.Algorithm, event.Severity, event.Message, attributes, event.OccurredAt.UTC(), a.now().UTC()); err != nil {
		return err
	}
	switch event.Type {
	case "hook":
		return a.ingestHookEvent(ctx, event, attributes)
	case "performance":
		return a.ingestPerformanceEvent(ctx, event, attributes)
	case "crash":
		return a.ingestCrashEvent(ctx, event, attributes)
	default:
		return nil
	}
}

func (a *Analytics) IngestDependency(ctx context.Context, dep control.Dependency, environmentID string) error {
	dep = control.NormalizeDependency(dep)
	if dep.ID == "" {
		dep.ID = control.NewID("dep")
	}
	if dep.ObservedAt.IsZero() {
		dep.ObservedAt = a.now().UTC()
	}
	licenses := dep.Licenses
	if licenses == nil {
		licenses = []string{}
	}
	vulnerabilities := dep.Vulnerabilities
	if vulnerabilities == nil {
		vulnerabilities = []control.DependencyVulnerability{}
	}
	vulnerabilitiesJSON, err := json.Marshal(vulnerabilities)
	if err != nil {
		return err
	}
	_, err = a.db.ExecContext(ctx, `
		INSERT INTO dependency_observations (
			id, application_id, environment_id, agent_id, name, version, ecosystem,
			package_path, licenses, vulnerabilities_json, observed_at, ingested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, dep.ID, dep.ApplicationID, environmentID, dep.AgentID, dep.Name, dep.Version, dep.Ecosystem, dep.PackagePath, licenses, string(vulnerabilitiesJSON), dep.ObservedAt.UTC(), a.now().UTC())
	return err
}

func (a *Analytics) ListEvents(ctx context.Context, query control.SecurityEventQuery) ([]control.SecurityEvent, error) {
	query = control.NormalizeSecurityEventQuery(query)
	sqlQuery := `
		SELECT id, type, application_id, environment_id, agent_id, policy_id, policy_version,
			hook, algorithm, severity, message, attributes_json, occurred_at
		FROM security_events
	`
	args := []any{}
	where := []string{}
	addFilter := func(column string, value any) {
		args = append(args, value)
		where = append(where, column+" = ?")
	}
	if query.Type != "" {
		addFilter("type", query.Type)
	}
	if query.ApplicationID != "" {
		addFilter("application_id", query.ApplicationID)
	}
	if query.EnvironmentID != "" {
		addFilter("environment_id", query.EnvironmentID)
	}
	if query.AgentID != "" {
		addFilter("agent_id", query.AgentID)
	}
	if query.PolicyID != "" {
		addFilter("policy_id", query.PolicyID)
	}
	if query.Severity != "" {
		addFilter("severity", query.Severity)
	}
	if query.Hook != "" {
		addFilter("hook", query.Hook)
	}
	if !query.OccurredAfter.IsZero() {
		args = append(args, query.OccurredAfter.UTC())
		where = append(where, "occurred_at >= ?")
	}
	if !query.OccurredBefore.IsZero() {
		args = append(args, query.OccurredBefore.UTC())
		where = append(where, "occurred_at <= ?")
	}
	if len(where) > 0 {
		sqlQuery += ` WHERE ` + strings.Join(where, " AND ")
	}
	args = append(args, uint64(query.Limit))
	sqlQuery += ` ORDER BY occurred_at DESC LIMIT ?`
	rows, err := a.db.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []control.SecurityEvent
	for rows.Next() {
		var event control.SecurityEvent
		var attributes string
		if err := rows.Scan(
			&event.ID,
			&event.Type,
			&event.ApplicationID,
			&event.EnvironmentID,
			&event.AgentID,
			&event.PolicyID,
			&event.PolicyVersion,
			&event.Hook,
			&event.Algorithm,
			&event.Severity,
			&event.Message,
			&attributes,
			&event.OccurredAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attributes), &event.Attributes); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (a *Analytics) DeleteEvents(ctx context.Context, ids []string) error {
	ids, err := control.NormalizeEventRecycleBinIDs(ids)
	if err != nil {
		return err
	}
	placeholders, args := clickHouseIDPlaceholders(ids)
	for _, table := range []string{"security_events", "hook_events", "performance_events", "crash_events"} {
		if _, err := a.db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s DELETE WHERE id IN (%s)`, table, placeholders), args...); err != nil {
			return err
		}
	}
	return nil
}

func (a *Analytics) EventOverview(ctx context.Context) (control.EventOverview, error) {
	overview := control.EventOverview{
		EventsByType:     map[string]int{},
		EventsBySeverity: map[string]int{},
	}
	if err := a.db.QueryRowContext(ctx, `SELECT count() FROM security_events`).Scan(&overview.EventCount); err != nil {
		return control.EventOverview{}, err
	}
	if err := scanCounts(ctx, a.db, `SELECT type, count() FROM security_events GROUP BY type`, overview.EventsByType); err != nil {
		return control.EventOverview{}, err
	}
	if err := scanCounts(ctx, a.db, `SELECT severity, count() FROM security_events GROUP BY severity`, overview.EventsBySeverity); err != nil {
		return control.EventOverview{}, err
	}
	return overview, nil
}

func (a *Analytics) CleanupOperationalData(ctx context.Context, request control.MaintenanceCleanupRequest) (control.MaintenanceCleanupReport, error) {
	request, err := control.NormalizeMaintenanceCleanupRequest(request)
	if err != nil {
		return control.MaintenanceCleanupReport{}, err
	}
	report := control.MaintenanceCleanupReport{
		ApplicationID: request.ApplicationID,
		Before:        request.Before,
		DryRun:        request.DryRun,
		Counts: map[string]int{
			"clickhouse_events":        0,
			"clickhouse_event_details": 0,
			"clickhouse_dependencies":  0,
			"clickhouse_rollups":       0,
		},
	}
	if request.IncludeEvents {
		events, err := a.countCleanupRows(ctx, "security_events", "occurred_at", request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		report.Counts["clickhouse_events"] = events
		for _, table := range []string{"hook_events", "performance_events", "crash_events"} {
			count, err := a.countCleanupRows(ctx, table, "occurred_at", request)
			if err != nil {
				return control.MaintenanceCleanupReport{}, err
			}
			report.Counts["clickhouse_event_details"] += count
		}
		rollups, err := a.countCleanupRows(ctx, "rule_overhead_rollups", "bucket_start", request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		report.Counts["clickhouse_rollups"] = rollups
		if !request.DryRun {
			for _, table := range []struct {
				name       string
				timeColumn string
			}{
				{"security_events", "occurred_at"},
				{"hook_events", "occurred_at"},
				{"performance_events", "occurred_at"},
				{"crash_events", "occurred_at"},
				{"rule_overhead_rollups", "bucket_start"},
			} {
				if err := a.deleteCleanupRows(ctx, table.name, table.timeColumn, request); err != nil {
					return control.MaintenanceCleanupReport{}, err
				}
			}
		}
	}
	if request.IncludeDependencies {
		count, err := a.countCleanupRows(ctx, "dependency_observations", "observed_at", request)
		if err != nil {
			return control.MaintenanceCleanupReport{}, err
		}
		report.Counts["clickhouse_dependencies"] = count
		if !request.DryRun {
			if err := a.deleteCleanupRows(ctx, "dependency_observations", "observed_at", request); err != nil {
				return control.MaintenanceCleanupReport{}, err
			}
		}
	}
	return report, nil
}

func (a *Analytics) Observability(ctx context.Context, query control.ObservabilityQuery) (control.ObservabilityReport, error) {
	ruleOverhead, err := a.ruleOverhead(ctx, query)
	if err != nil {
		return control.ObservabilityReport{}, err
	}
	hookLatency, err := a.hookLatency(ctx, query)
	if err != nil {
		return control.ObservabilityReport{}, err
	}
	agentOverhead, err := a.agentOverhead(ctx, query)
	if err != nil {
		return control.ObservabilityReport{}, err
	}
	policyPerformance, err := a.policyPerformance(ctx, query)
	if err != nil {
		return control.ObservabilityReport{}, err
	}
	return control.ObservabilityReport{
		RuleOverhead:      ruleOverhead,
		HookLatency:       hookLatency,
		AgentOverhead:     agentOverhead,
		PolicyPerformance: policyPerformance,
	}, nil
}

func (a *Analytics) RuleOverhead(ctx context.Context, applicationID string, policyID string) ([]RuleOverhead, error) {
	query := `
		SELECT policy_id, policy_version, rule_id, hook, sum(executions), sum(blocked),
			avg(avg_latency_us) AS avg_latency_us,
			max(p95_latency_us) AS p95_latency_us,
			max(max_latency_us) AS max_latency_us
		FROM rule_overhead_rollups
		WHERE application_id = ?
	`
	args := []any{applicationID}
	if policyID != "" {
		query += ` AND policy_id = ?`
		args = append(args, policyID)
	}
	query += ` GROUP BY policy_id, policy_version, rule_id, hook ORDER BY p95_latency_us DESC LIMIT 100`
	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var overhead []RuleOverhead
	for rows.Next() {
		var item RuleOverhead
		if err := rows.Scan(&item.PolicyID, &item.PolicyVersion, &item.RuleID, &item.Hook, &item.Executions, &item.Blocked, &item.AverageLatencyUS, &item.P95LatencyUS, &item.MaxLatencyUS); err != nil {
			return nil, err
		}
		overhead = append(overhead, item)
	}
	return overhead, rows.Err()
}

func (a *Analytics) ruleOverhead(ctx context.Context, query control.ObservabilityQuery) ([]control.RuleOverhead, error) {
	sqlText := `
		SELECT policy_id, policy_version, rule_id, hook, sum(executions), sum(blocked),
			avg(avg_latency_us) AS avg_latency_us,
			max(p95_latency_us) AS p95_latency_us,
			max(max_latency_us) AS max_latency_us
		FROM rule_overhead_rollups
	`
	where, args := observabilityWhere(query)
	sqlText += where
	sqlText += ` GROUP BY policy_id, policy_version, rule_id, hook ORDER BY p95_latency_us DESC LIMIT 100`
	rows, err := a.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []control.RuleOverhead
	for rows.Next() {
		var item control.RuleOverhead
		var policyVersion uint32
		var executions uint64
		var blocked uint64
		var p95LatencyUS uint64
		var maxLatencyUS uint64
		if err := rows.Scan(&item.PolicyID, &policyVersion, &item.RuleID, &item.Hook, &executions, &blocked, &item.AverageLatencyUS, &p95LatencyUS, &maxLatencyUS); err != nil {
			return nil, err
		}
		item.PolicyVersion = int(policyVersion)
		item.Executions = intFromUint64(executions)
		item.Blocked = intFromUint64(blocked)
		item.P95LatencyUS = intFromUint64(p95LatencyUS)
		item.MaxLatencyUS = intFromUint64(maxLatencyUS)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *Analytics) hookLatency(ctx context.Context, query control.ObservabilityQuery) ([]control.HookLatency, error) {
	sqlText := `
		SELECT hook, count(), avg(latency_us), toUInt64(quantile(0.95)(latency_us)), max(latency_us)
		FROM hook_events
	`
	where, args := observabilityWhere(query)
	sqlText += where
	sqlText += ` GROUP BY hook ORDER BY 4 DESC LIMIT 100`
	rows, err := a.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []control.HookLatency
	for rows.Next() {
		var item control.HookLatency
		var calls uint64
		var p95LatencyUS uint64
		var maxLatencyUS uint64
		if err := rows.Scan(&item.Hook, &calls, &item.AverageLatencyUS, &p95LatencyUS, &maxLatencyUS); err != nil {
			return nil, err
		}
		item.Calls = intFromUint64(calls)
		item.P95LatencyUS = intFromUint64(p95LatencyUS)
		item.MaxLatencyUS = intFromUint64(maxLatencyUS)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *Analytics) agentOverhead(ctx context.Context, query control.ObservabilityQuery) ([]control.AgentOverhead, error) {
	sqlText := `
		SELECT agent_id, count(), avg(cpu_overhead_pct), toInt64(avg(memory_overhead_bytes)),
			max(hook_latency_p95_us), max(rule_eval_p95_us)
		FROM performance_events
	`
	where, args := observabilityWhere(query)
	sqlText += where
	sqlText += ` GROUP BY agent_id ORDER BY 5 DESC LIMIT 100`
	rows, err := a.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []control.AgentOverhead
	for rows.Next() {
		var item control.AgentOverhead
		var samples uint64
		var hookLatencyP95US uint64
		var ruleEvalP95US uint64
		if err := rows.Scan(&item.AgentID, &samples, &item.CPUOverheadPCT, &item.MemoryOverheadBytes, &hookLatencyP95US, &ruleEvalP95US); err != nil {
			return nil, err
		}
		item.Samples = intFromUint64(samples)
		item.HookLatencyP95US = intFromUint64(hookLatencyP95US)
		item.RuleEvalP95US = intFromUint64(ruleEvalP95US)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *Analytics) policyPerformance(ctx context.Context, query control.ObservabilityQuery) ([]control.PolicyPerformance, error) {
	sqlText := `
		SELECT policy_id, policy_version, count(), avg(cpu_overhead_pct),
			max(hook_latency_p95_us), max(rule_eval_p95_us)
		FROM performance_events
	`
	where, args := observabilityWhere(query)
	sqlText += where
	sqlText += ` GROUP BY policy_id, policy_version ORDER BY 5 DESC LIMIT 100`
	rows, err := a.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []control.PolicyPerformance
	for rows.Next() {
		var item control.PolicyPerformance
		var policyVersion uint32
		var samples uint64
		var hookLatencyP95US uint64
		var ruleEvalP95US uint64
		if err := rows.Scan(&item.PolicyID, &policyVersion, &samples, &item.CPUOverheadPCT, &hookLatencyP95US, &ruleEvalP95US); err != nil {
			return nil, err
		}
		item.PolicyVersion = int(policyVersion)
		item.Samples = intFromUint64(samples)
		item.HookLatencyP95US = intFromUint64(hookLatencyP95US)
		item.RuleEvalP95US = intFromUint64(ruleEvalP95US)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (a *Analytics) RecordRuleOverhead(ctx context.Context, sample RuleOverheadSample) error {
	if sample.BucketStart.IsZero() {
		sample.BucketStart = a.now().UTC().Truncate(time.Minute)
	}
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO rule_overhead_rollups (
			bucket_start, application_id, environment_id, policy_id, policy_version, rule_id, hook,
			executions, blocked, avg_latency_us, p95_latency_us, max_latency_us
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, sample.BucketStart.UTC(), sample.ApplicationID, sample.EnvironmentID, sample.PolicyID, sample.PolicyVersion, sample.RuleID, sample.Hook, sample.Executions, sample.Blocked, sample.AverageLatencyUS, sample.P95LatencyUS, sample.MaxLatencyUS)
	return err
}

func (a *Analytics) ingestHookEvent(ctx context.Context, event control.SecurityEvent, attributes string) error {
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO hook_events (
			id, application_id, environment_id, agent_id, policy_id, policy_version,
			hook, class_name, method_name, action, latency_us, attributes_json, occurred_at, ingested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.ApplicationID, event.EnvironmentID, event.AgentID, event.PolicyID, event.PolicyVersion, event.Hook, attrString(event.Attributes, "class_name"), attrString(event.Attributes, "method_name"), attrString(event.Attributes, "action"), attrUInt64(event.Attributes, "latency_us"), attributes, event.OccurredAt.UTC(), a.now().UTC())
	return err
}

func (a *Analytics) ingestPerformanceEvent(ctx context.Context, event control.SecurityEvent, attributes string) error {
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO performance_events (
			id, application_id, environment_id, agent_id, policy_id, policy_version,
			cpu_overhead_pct, memory_overhead_bytes, hook_latency_p50_us, hook_latency_p95_us,
			rule_eval_p95_us, attributes_json, occurred_at, ingested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.ApplicationID, event.EnvironmentID, event.AgentID, event.PolicyID, event.PolicyVersion, attrFloat64(event.Attributes, "cpu_overhead_pct"), attrInt64(event.Attributes, "memory_overhead_bytes"), attrUInt64(event.Attributes, "hook_latency_p50_us"), attrUInt64(event.Attributes, "hook_latency_p95_us"), attrUInt64(event.Attributes, "rule_eval_p95_us"), attributes, event.OccurredAt.UTC(), a.now().UTC())
	return err
}

func (a *Analytics) ingestCrashEvent(ctx context.Context, event control.SecurityEvent, attributes string) error {
	_, err := a.db.ExecContext(ctx, `
		INSERT INTO crash_events (
			id, application_id, environment_id, agent_id, runtime, agent_version,
			error_class, message, stack_trace, attributes_json, occurred_at, ingested_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, event.ID, event.ApplicationID, event.EnvironmentID, event.AgentID, attrString(event.Attributes, "runtime"), attrString(event.Attributes, "agent_version"), attrString(event.Attributes, "error_class"), event.Message, attrString(event.Attributes, "stack_trace"), attributes, event.OccurredAt.UTC(), a.now().UTC())
	return err
}

func marshalAttributes(attributes map[string]any) (string, error) {
	if attributes == nil {
		return "{}", nil
	}
	body, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func attrString(attributes map[string]any, key string) string {
	value, ok := attributes[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(value)
	}
}

func attrUInt64(attributes map[string]any, key string) uint64 {
	value, ok := attributes[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case uint64:
		return typed
	case uint:
		return uint64(typed)
	case int:
		if typed < 0 {
			return 0
		}
		return uint64(typed)
	case int64:
		if typed < 0 {
			return 0
		}
		return uint64(typed)
	case float64:
		if typed < 0 {
			return 0
		}
		return uint64(typed)
	case json.Number:
		parsed, _ := strconv.ParseUint(string(typed), 10, 64)
		return parsed
	case string:
		parsed, _ := strconv.ParseUint(typed, 10, 64)
		return parsed
	default:
		return 0
	}
}

func attrInt64(attributes map[string]any, key string) int64 {
	value, ok := attributes[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := strconv.ParseInt(string(typed), 10, 64)
		return parsed
	case string:
		parsed, _ := strconv.ParseInt(typed, 10, 64)
		return parsed
	default:
		return 0
	}
}

func attrFloat64(attributes map[string]any, key string) float64 {
	value, ok := attributes[key]
	if !ok || value == nil {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		parsed, _ := strconv.ParseFloat(string(typed), 64)
		return parsed
	case string:
		parsed, _ := strconv.ParseFloat(typed, 64)
		return parsed
	default:
		return 0
	}
}

func scanCounts(ctx context.Context, db *sql.DB, query string, target map[string]int) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count uint64
		if err := rows.Scan(&key, &count); err != nil {
			return err
		}
		target[key] = int(count)
	}
	return rows.Err()
}

func observabilityWhere(query control.ObservabilityQuery) (string, []any) {
	var clauses []string
	var args []any
	if query.ApplicationID != "" {
		clauses = append(clauses, "application_id = ?")
		args = append(args, query.ApplicationID)
	}
	if query.PolicyID != "" {
		clauses = append(clauses, "policy_id = ?")
		args = append(args, query.PolicyID)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (a *Analytics) countCleanupRows(ctx context.Context, table string, timeColumn string, request control.MaintenanceCleanupRequest) (int, error) {
	where, args := clickHouseCleanupWhere(timeColumn, request)
	var count uint64
	if err := a.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT count() FROM %s %s`, table, where), args...).Scan(&count); err != nil {
		return 0, err
	}
	return intFromUint64(count), nil
}

func (a *Analytics) deleteCleanupRows(ctx context.Context, table string, timeColumn string, request control.MaintenanceCleanupRequest) error {
	where, args := clickHouseCleanupWhere(timeColumn, request)
	_, err := a.db.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE %s DELETE %s`, table, where), args...)
	return err
}

func clickHouseCleanupWhere(timeColumn string, request control.MaintenanceCleanupRequest) (string, []any) {
	args := []any{request.Before}
	clauses := []string{fmt.Sprintf("%s < ?", timeColumn)}
	if request.ApplicationID != "" {
		clauses = append(clauses, "application_id = ?")
		args = append(args, request.ApplicationID)
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

func clickHouseIDPlaceholders(ids []string) (string, []any) {
	parts := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, "?")
		args = append(args, id)
	}
	return strings.Join(parts, ", "), args
}

func intFromUint64(value uint64) int {
	maxInt := uint64(^uint(0) >> 1)
	if value > maxInt {
		return int(maxInt)
	}
	return int(value)
}

type RuleOverhead struct {
	PolicyID         string  `json:"policy_id"`
	PolicyVersion    uint32  `json:"policy_version"`
	RuleID           string  `json:"rule_id"`
	Hook             string  `json:"hook"`
	Executions       uint64  `json:"executions"`
	Blocked          uint64  `json:"blocked"`
	AverageLatencyUS float64 `json:"average_latency_us"`
	P95LatencyUS     uint64  `json:"p95_latency_us"`
	MaxLatencyUS     uint64  `json:"max_latency_us"`
}

type RuleOverheadSample struct {
	BucketStart      time.Time
	ApplicationID    string
	EnvironmentID    string
	PolicyID         string
	PolicyVersion    uint32
	RuleID           string
	Hook             string
	Executions       uint64
	Blocked          uint64
	AverageLatencyUS float64
	P95LatencyUS     uint64
	MaxLatencyUS     uint64
}
