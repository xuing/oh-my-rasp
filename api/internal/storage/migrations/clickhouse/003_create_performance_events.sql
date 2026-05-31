CREATE TABLE IF NOT EXISTS performance_events (
	id String,
	application_id String,
	environment_id String,
	agent_id String,
	policy_id String,
	policy_version UInt32,
	cpu_overhead_pct Float64,
	memory_overhead_bytes Int64,
	hook_latency_p50_us UInt64,
	hook_latency_p95_us UInt64,
	rule_eval_p95_us UInt64,
	attributes_json String,
	occurred_at DateTime64(3, 'UTC'),
	ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (application_id, environment_id, occurred_at, agent_id);
