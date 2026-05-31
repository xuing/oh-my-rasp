CREATE TABLE IF NOT EXISTS baseline_findings (
	id TEXT PRIMARY KEY,
	application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
	environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
	agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
	check_id TEXT NOT NULL,
	title TEXT NOT NULL,
	category TEXT NOT NULL DEFAULT 'runtime',
	severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
	status TEXT NOT NULL CHECK (status IN ('failed', 'warning', 'passed', 'suppressed')),
	resource TEXT NOT NULL DEFAULT '',
	remediation TEXT NOT NULL DEFAULT '',
	attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
	observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (application_id, environment_id, agent_id, check_id, resource)
);

CREATE INDEX IF NOT EXISTS idx_baseline_findings_scope_status
	ON baseline_findings (application_id, environment_id, agent_id, status, severity);

CREATE INDEX IF NOT EXISTS idx_baseline_findings_observed
	ON baseline_findings (observed_at DESC);
