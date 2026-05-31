CREATE INDEX IF NOT EXISTS idx_event_ingest_outbox_type_time ON event_ingest_outbox (type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_event_ingest_outbox_delivery ON event_ingest_outbox (delivered_to_clickhouse_at, ingested_at)
WHERE delivered_to_clickhouse_at IS NULL;
