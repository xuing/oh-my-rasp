CREATE TABLE IF NOT EXISTS policies (
	id TEXT PRIMARY KEY,
	organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	archived_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (organization_id, name)
);
