ALTER TABLE applications
  ADD COLUMN IF NOT EXISTS agent_secret_value TEXT;

UPDATE applications
SET agent_secret_value = 'dev-app-secret'
WHERE id = 'app_default'
  AND agent_secret_value IS NULL
  AND secret_hash = '5662fb4c37080e96b2b0922134ef8591e5626f1ebd54580ba05c121af2b1afd3';
