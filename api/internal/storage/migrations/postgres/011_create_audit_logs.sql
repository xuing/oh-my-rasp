CREATE TABLE IF NOT EXISTS audit_logs (
	id TEXT PRIMARY KEY,
	actor_id TEXT,
	action TEXT NOT NULL,
	resource TEXT NOT NULL,
	details JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
