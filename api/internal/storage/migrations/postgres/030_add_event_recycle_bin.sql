ALTER TABLE event_ingest_outbox
	ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ,
	ADD COLUMN IF NOT EXISTS deleted_by TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_event_ingest_outbox_active_time
	ON event_ingest_outbox (type, occurred_at DESC)
	WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_event_ingest_outbox_deleted_time
	ON event_ingest_outbox (deleted_at DESC)
	WHERE deleted_at IS NOT NULL;
