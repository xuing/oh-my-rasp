CREATE INDEX IF NOT EXISTS idx_alert_deliveries_created_at ON alert_deliveries (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_status ON alert_deliveries (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_deliveries_target ON alert_deliveries (target, created_at DESC);
