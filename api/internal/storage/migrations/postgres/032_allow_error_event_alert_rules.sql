ALTER TABLE alert_rules
	DROP CONSTRAINT IF EXISTS alert_rules_event_type_check;

ALTER TABLE alert_rules
	ADD CONSTRAINT alert_rules_event_type_check
	CHECK (event_type IN ('attack', 'hook', 'performance', 'crash', 'error', 'dependency'));
