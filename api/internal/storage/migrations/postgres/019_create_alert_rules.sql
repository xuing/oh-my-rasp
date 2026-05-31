CREATE TABLE IF NOT EXISTS alert_rules (
	id TEXT PRIMARY KEY,
	organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	enabled BOOLEAN NOT NULL DEFAULT true,
	event_type TEXT NOT NULL,
	severity TEXT NOT NULL,
	condition TEXT NOT NULL DEFAULT 'true',
	target TEXT NOT NULL,
	created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CHECK (event_type IN ('attack', 'hook', 'performance', 'crash', 'dependency')),
	CHECK (severity IN ('critical', 'high', 'medium', 'low'))
);
