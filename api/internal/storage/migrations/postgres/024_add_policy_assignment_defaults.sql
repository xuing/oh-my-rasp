ALTER TABLE organizations
	ADD COLUMN IF NOT EXISTS policy_id TEXT,
	ADD COLUMN IF NOT EXISTS policy_version INTEGER;

ALTER TABLE applications
	ADD COLUMN IF NOT EXISTS policy_id TEXT,
	ADD COLUMN IF NOT EXISTS policy_version INTEGER;

ALTER TABLE environments
	ADD COLUMN IF NOT EXISTS policy_id TEXT,
	ADD COLUMN IF NOT EXISTS policy_version INTEGER;

CREATE INDEX IF NOT EXISTS idx_applications_policy_assignment
	ON applications (policy_id, policy_version)
	WHERE policy_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_environments_policy_assignment
	ON environments (policy_id, policy_version)
	WHERE policy_id IS NOT NULL;
