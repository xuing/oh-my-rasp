CREATE TABLE IF NOT EXISTS hook_events (
	id String,
	application_id String,
	environment_id String,
	agent_id String,
	policy_id String,
	policy_version UInt32,
	hook LowCardinality(String),
	class_name String,
	method_name String,
	action LowCardinality(String),
	latency_us UInt64,
	attributes_json String,
	occurred_at DateTime64(3, 'UTC'),
	ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (application_id, environment_id, hook, occurred_at);
