CREATE TABLE IF NOT EXISTS agents (
	id TEXT PRIMARY KEY,
	application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
	environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
	hostname TEXT NOT NULL,
	runtime TEXT NOT NULL,
	version TEXT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('online', 'offline', 'degraded', 'disabled')),
	last_seen_at TIMESTAMPTZ NOT NULL,
	policy_id TEXT REFERENCES policies(id) ON DELETE SET NULL,
	policy_version INTEGER,
	labels JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
