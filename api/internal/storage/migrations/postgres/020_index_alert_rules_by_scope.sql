CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled_severity ON alert_rules (enabled, severity);
CREATE INDEX IF NOT EXISTS idx_alert_rules_event_type ON alert_rules (event_type);
