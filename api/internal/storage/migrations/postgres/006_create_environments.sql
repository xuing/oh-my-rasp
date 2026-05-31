CREATE TABLE IF NOT EXISTS environments (
	id TEXT PRIMARY KEY,
	application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (application_id, name)
);
