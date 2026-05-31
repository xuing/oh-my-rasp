CREATE TABLE IF NOT EXISTS dependency_observations (
	id String,
	application_id String,
	environment_id String,
	agent_id String,
	name String,
	version String,
	ecosystem LowCardinality(String),
	package_path String,
	licenses Array(String),
	vulnerabilities_json String,
	observed_at DateTime64(3, 'UTC'),
	ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
) ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(observed_at)
ORDER BY (application_id, ecosystem, name, version, agent_id);
