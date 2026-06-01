ALTER TABLE alert_rules
	ADD COLUMN IF NOT EXISTS application_id TEXT REFERENCES applications(id) ON DELETE CASCADE;

ALTER TABLE alert_deliveries
	ADD COLUMN IF NOT EXISTS application_id TEXT REFERENCES applications(id) ON DELETE CASCADE;

UPDATE alert_deliveries d
SET application_id = e.application_id
FROM event_ingest_outbox e
WHERE d.event_id = e.id
	AND d.application_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_alert_rules_application_enabled
	ON alert_rules (application_id, enabled, event_type, severity);

CREATE INDEX IF NOT EXISTS idx_alert_deliveries_application_created
	ON alert_deliveries (application_id, created_at DESC);
