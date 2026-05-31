CREATE INDEX IF NOT EXISTS idx_agents_environment_status ON agents (environment_id, status, last_seen_at DESC);
