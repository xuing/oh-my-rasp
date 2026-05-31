CREATE TABLE IF NOT EXISTS alert_deliveries (
	id TEXT PRIMARY KEY,
	organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	alert_rule_id TEXT NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
	alert_rule_name TEXT NOT NULL,
	event_id TEXT NOT NULL REFERENCES event_ingest_outbox(id) ON DELETE CASCADE,
	event_type TEXT NOT NULL,
	severity TEXT NOT NULL,
	target TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'queued',
	attempts INTEGER NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	delivered_at TIMESTAMPTZ,
	UNIQUE (alert_rule_id, event_id),
	CHECK (severity IN ('critical', 'high', 'medium', 'low')),
	CHECK (status IN ('queued', 'delivered', 'failed')),
	CHECK (attempts >= 0)
);
