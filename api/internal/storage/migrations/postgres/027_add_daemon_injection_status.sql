ALTER TABLE daemon_workloads
  ADD COLUMN IF NOT EXISTS injection_status TEXT,
  ADD COLUMN IF NOT EXISTS injection_error TEXT,
  ADD COLUMN IF NOT EXISTS injection_helper_id TEXT,
  ADD COLUMN IF NOT EXISTS injection_helper_version TEXT,
  ADD COLUMN IF NOT EXISTS injection_reported_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS injection_status_updated_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_daemon_workloads_injection_status
  ON daemon_workloads(injection_status, injection_status_updated_at DESC);
