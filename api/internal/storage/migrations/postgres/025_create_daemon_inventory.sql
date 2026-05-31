CREATE TABLE IF NOT EXISTS daemon_settings (
  id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
  access_token TEXT NOT NULL,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS daemon_workloads (
  id TEXT PRIMARY KEY,
  application_id TEXT REFERENCES applications(id) ON DELETE SET NULL,
  node_name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('process', 'container')),
  pid INTEGER,
  cmdline JSONB NOT NULL DEFAULT '[]'::jsonb,
  container_id TEXT,
  container_name TEXT,
  image_id TEXT,
  image_tag TEXT,
  observed_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_daemon_workloads_application
  ON daemon_workloads(application_id);

CREATE INDEX IF NOT EXISTS idx_daemon_workloads_node_updated
  ON daemon_workloads(node_name, updated_at DESC);
