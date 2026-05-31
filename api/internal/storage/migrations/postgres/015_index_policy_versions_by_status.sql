CREATE INDEX IF NOT EXISTS idx_policy_versions_status ON policy_versions (policy_id, status, version DESC);
