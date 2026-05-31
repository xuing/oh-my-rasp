CREATE INDEX IF NOT EXISTS idx_users_organization_disabled ON users (organization_id, disabled_at);
CREATE INDEX IF NOT EXISTS idx_users_roles ON users USING GIN (roles);
