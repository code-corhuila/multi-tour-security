-- The requests of a tenant by status, and the ones an administrator asked for, most recent first (HU-SEC-007, plan D-04)
CREATE INDEX idx_support_access_tenant_status_requested_at ON security.support_access (tenant_id, status, requested_at DESC);
CREATE INDEX idx_support_access_requested_by_requested_at ON security.support_access (requested_by, requested_at DESC);
