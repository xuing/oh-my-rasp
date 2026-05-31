CREATE TABLE IF NOT EXISTS rule_overhead_rollups (
	bucket_start DateTime64(3, 'UTC'),
	application_id String,
	environment_id String,
	policy_id String,
	policy_version UInt32,
	rule_id String,
	hook LowCardinality(String),
	executions UInt64,
	blocked UInt64,
	avg_latency_us Float64,
	p95_latency_us UInt64,
	max_latency_us UInt64
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(bucket_start)
ORDER BY (application_id, environment_id, policy_id, policy_version, rule_id, bucket_start);
