CREATE TABLE IF NOT EXISTS event_ingest_outbox (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL,
	application_id TEXT NOT NULL,
	environment_id TEXT NOT NULL,
	agent_id TEXT NOT NULL,
	policy_id TEXT,
	policy_version INTEGER NOT NULL DEFAULT 0,
	hook TEXT NOT NULL DEFAULT '',
	algorithm TEXT NOT NULL DEFAULT '',
	severity TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL,
	attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
	occurred_at TIMESTAMPTZ NOT NULL,
	ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	delivered_to_clickhouse_at TIMESTAMPTZ
);
