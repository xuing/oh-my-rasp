ALTER TABLE applications
  ADD COLUMN IF NOT EXISTS agent_secret_value TEXT;

UPDATE applications
SET agent_secret_value = 'ohmyrasp_' || md5(random()::text || clock_timestamp()::text || id)
WHERE agent_secret_value IS NULL;
