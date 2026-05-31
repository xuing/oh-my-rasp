CREATE TABLE IF NOT EXISTS crash_events (
	id String,
	application_id String,
	environment_id String,
	agent_id String,
	runtime LowCardinality(String),
	agent_version String,
	error_class String,
	message String,
	stack_trace String,
	attributes_json String,
	occurred_at DateTime64(3, 'UTC'),
	ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (application_id, environment_id, occurred_at, error_class);
