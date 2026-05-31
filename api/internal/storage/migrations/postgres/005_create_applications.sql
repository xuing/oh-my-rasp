CREATE TABLE IF NOT EXISTS applications (
	id TEXT PRIMARY KEY,
	organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	secret_hash TEXT NOT NULL,
	secret_preview TEXT NOT NULL,
	deleted_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (organization_id, name)
);
