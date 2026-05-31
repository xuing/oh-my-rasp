CREATE TABLE IF NOT EXISTS dependency_inventory (
	id TEXT PRIMARY KEY,
	application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
	agent_id TEXT REFERENCES agents(id) ON DELETE SET NULL,
	name TEXT NOT NULL,
	version TEXT NOT NULL,
	ecosystem TEXT NOT NULL,
	first_observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	last_observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (application_id, name, version, ecosystem)
);
