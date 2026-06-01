package migrations

import (
	"strings"
	"testing"
)

func TestPostgresMigrationsAreSequentialAndCoverControlPlaneTables(t *testing.T) {
	got, err := List(Postgres)
	if err != nil {
		t.Fatalf("list postgres migrations: %v", err)
	}
	if len(got) != 34 {
		t.Fatalf("expected 34 postgres migrations, got %d", len(got))
	}
	combined := combineSQL(got)
	required := []string{
		"CREATE EXTENSION IF NOT EXISTS citext",
		"CREATE TABLE IF NOT EXISTS organizations",
		"CREATE TABLE IF NOT EXISTS users",
		"CREATE TABLE IF NOT EXISTS sessions",
		"CREATE TABLE IF NOT EXISTS applications",
		"CREATE TABLE IF NOT EXISTS environments",
		"CREATE TABLE IF NOT EXISTS agents",
		"CREATE TABLE IF NOT EXISTS policies",
		"CREATE TABLE IF NOT EXISTS policy_versions",
		"CREATE TABLE IF NOT EXISTS dependency_inventory",
		"CREATE TABLE IF NOT EXISTS audit_logs",
		"CREATE TABLE IF NOT EXISTS system_settings",
		"CREATE TABLE IF NOT EXISTS alert_rules",
		"CREATE TABLE IF NOT EXISTS alert_deliveries",
		"CREATE TABLE IF NOT EXISTS event_ingest_outbox",
		"CREATE TABLE IF NOT EXISTS daemon_settings",
		"CREATE TABLE IF NOT EXISTS daemon_workloads",
		"agent_secret_value",
		"injection_status",
		"idx_alert_rules_enabled_severity",
		"idx_alert_deliveries_status",
		"idx_applications_policy_assignment",
		"idx_environments_policy_assignment",
		"idx_daemon_workloads_application",
		"idx_daemon_workloads_node_updated",
		"idx_daemon_workloads_injection_status",
		"ALTER TABLE organizations",
		"idx_users_organization_disabled",
		"idx_users_roles",
		"CHECK (canary_percent BETWEEN 0 AND 100)",
		"roles TEXT[] NOT NULL",
		"rules JSONB NOT NULL",
		"delivered_to_clickhouse_at",
		"package_path",
		"vulnerabilities JSONB",
		"idx_dependency_inventory_vulnerabilities",
		"CREATE TABLE IF NOT EXISTS baseline_findings",
		"idx_baseline_findings_scope_status",
		"deleted_at TIMESTAMPTZ",
		"idx_event_ingest_outbox_deleted_time",
		"ignored_at TIMESTAMPTZ",
		"idx_agents_ignored_last_seen",
		"alert_rules_event_type_check",
		"'error'",
		"CREATE TABLE IF NOT EXISTS application_settings",
		"idx_application_settings_app_key",
		"idx_application_settings_environment_key",
		"DELETE FROM system_settings",
		"ADD COLUMN IF NOT EXISTS application_id TEXT REFERENCES applications(id) ON DELETE CASCADE",
		"idx_alert_rules_application_enabled",
		"idx_alert_deliveries_application_created",
	}
	for _, fragment := range required {
		if !strings.Contains(combined, fragment) {
			t.Fatalf("postgres migrations missing %q", fragment)
		}
	}
}

func TestClickHouseMigrationsCoverEventAndOverheadPipelines(t *testing.T) {
	got, err := List(ClickHouse)
	if err != nil {
		t.Fatalf("list clickhouse migrations: %v", err)
	}
	if len(got) != 6 {
		t.Fatalf("expected 6 clickhouse migrations, got %d", len(got))
	}
	combined := combineSQL(got)
	required := []string{
		"CREATE TABLE IF NOT EXISTS security_events",
		"CREATE TABLE IF NOT EXISTS hook_events",
		"CREATE TABLE IF NOT EXISTS performance_events",
		"CREATE TABLE IF NOT EXISTS crash_events",
		"CREATE TABLE IF NOT EXISTS dependency_observations",
		"CREATE TABLE IF NOT EXISTS rule_overhead_rollups",
		"ENGINE = MergeTree",
		"ENGINE = ReplacingMergeTree",
		"ENGINE = SummingMergeTree",
		"p95_latency_us",
		"policy_version UInt32",
	}
	for _, fragment := range required {
		if !strings.Contains(combined, fragment) {
			t.Fatalf("clickhouse migrations missing %q", fragment)
		}
	}
}

func TestApplicationSettingsMigrationBackfillsMovedGlobalSettings(t *testing.T) {
	got, err := List(Postgres)
	if err != nil {
		t.Fatalf("list postgres migrations: %v", err)
	}
	migration := got[32]
	if migration.Name != "033_create_application_settings.sql" {
		t.Fatalf("expected application settings migration at 033, got %s", migration.Name)
	}
	required := []string{
		"CREATE TABLE IF NOT EXISTS application_settings",
		"CROSS JOIN moved_settings",
		"LEFT JOIN system_settings s ON s.key = m.key",
		"COALESCE(s.value, m.default_value)",
		"ON CONFLICT (application_id, key) WHERE environment_id IS NULL DO NOTHING",
		"DELETE FROM system_settings",
		"'alerts.delivery'",
		"'dependency.vulnerability_policy'",
		"'protection.allowlist'",
		"'protection.hardening'",
	}
	for _, fragment := range required {
		if !strings.Contains(migration.SQL, fragment) {
			t.Fatalf("application settings migration missing %q", fragment)
		}
	}
}

func TestUnsupportedDialectIsRejected(t *testing.T) {
	if _, err := List(Dialect("sqlite")); err == nil {
		t.Fatal("expected unsupported dialect error")
	}
}

func TestRecordMigrationStatementUsesDriverPlaceholders(t *testing.T) {
	if got := recordMigrationStatement(Postgres); !strings.Contains(got, "$1") {
		t.Fatalf("expected postgres placeholders, got %q", got)
	}
	if got := recordMigrationStatement(ClickHouse); !strings.Contains(got, "?") {
		t.Fatalf("expected clickhouse placeholders, got %q", got)
	}
}

func combineSQL(migrations []Migration) string {
	var builder strings.Builder
	for i, migration := range migrations {
		if migration.Version != i+1 {
			panic("migration list is not sequential")
		}
		builder.WriteString(migration.SQL)
		builder.WriteByte('\n')
	}
	return builder.String()
}
