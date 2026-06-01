CREATE TABLE IF NOT EXISTS application_settings (
	application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
	environment_id TEXT REFERENCES environments(id) ON DELETE CASCADE,
	key TEXT NOT NULL,
	value JSONB NOT NULL,
	updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_application_settings_app_key
	ON application_settings (application_id, key)
	WHERE environment_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_application_settings_environment
	ON application_settings (environment_id, key)
	WHERE environment_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_application_settings_environment_key
	ON application_settings (application_id, environment_id, key)
	WHERE environment_id IS NOT NULL;

WITH moved_settings(key, default_value) AS (
	VALUES
		('alerts.delivery', '{"interval_seconds":300}'::jsonb),
		('dependency.vulnerability_policy', '{"fail_on_severity":"critical","block_known_exploited":true}'::jsonb),
		('protection.allowlist', '{"enabled":false,"mode":"monitor","entries":[]}'::jsonb),
		('protection.hardening', '{"mode":"monitor","block_reflection_abuse":true,"block_process_execution":true}'::jsonb)
)
INSERT INTO application_settings (application_id, environment_id, key, value, updated_by, updated_at)
SELECT
	a.id,
	NULL,
	m.key,
	COALESCE(s.value, m.default_value),
	s.updated_by,
	COALESCE(s.updated_at, now())
FROM applications a
CROSS JOIN moved_settings m
LEFT JOIN system_settings s ON s.key = m.key
WHERE a.deleted_at IS NULL
ON CONFLICT (application_id, key) WHERE environment_id IS NULL DO NOTHING;

DELETE FROM system_settings
WHERE key IN (
	'alerts.delivery',
	'dependency.vulnerability_policy',
	'protection.allowlist',
	'protection.hardening'
);
