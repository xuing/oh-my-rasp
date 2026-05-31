ALTER TABLE dependency_inventory
	ADD COLUMN IF NOT EXISTS package_path TEXT NOT NULL DEFAULT '',
	ADD COLUMN IF NOT EXISTS licenses JSONB NOT NULL DEFAULT '[]'::jsonb,
	ADD COLUMN IF NOT EXISTS vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_dependency_inventory_vulnerabilities
	ON dependency_inventory USING GIN (vulnerabilities);

CREATE INDEX IF NOT EXISTS idx_dependency_inventory_last_observed
	ON dependency_inventory (last_observed_at DESC);
