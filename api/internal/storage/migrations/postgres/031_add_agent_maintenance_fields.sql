ALTER TABLE agents
	ADD COLUMN IF NOT EXISTS alias TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS ignored_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_agents_ignored_last_seen
	ON agents(ignored_at, last_seen_at DESC);
