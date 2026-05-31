CREATE TABLE IF NOT EXISTS security_events (
	id String,
	type LowCardinality(String),
	application_id String,
	environment_id String,
	agent_id String,
	policy_id String,
	policy_version UInt32,
	hook LowCardinality(String),
	algorithm LowCardinality(String),
	severity LowCardinality(String),
	message String,
	attributes_json String,
	occurred_at DateTime64(3, 'UTC'),
	ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (application_id, environment_id, occurred_at, severity, hook);
