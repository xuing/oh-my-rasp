CREATE TABLE IF NOT EXISTS policy_versions (
	policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
	version INTEGER NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('draft', 'canary', 'active', 'rolled_back', 'archived')),
	rules JSONB NOT NULL DEFAULT '[]'::jsonb,
	canary_percent INTEGER NOT NULL DEFAULT 0 CHECK (canary_percent BETWEEN 0 AND 100),
	created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	published_at TIMESTAMPTZ,
	PRIMARY KEY (policy_id, version)
);
