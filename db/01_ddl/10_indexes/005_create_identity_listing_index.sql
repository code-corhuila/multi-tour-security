-- The listing of the users of a tenant, newest first, with the identifier as the tie-break so that a page is stable
-- (HU-SEC-005, plan D-04). It is built CONCURRENTLY and in its own changeset, because the table already holds accounts
-- and an index built the ordinary way would block the sign-in while it is made (norm §5.2). If it fails half way PostgreSQL
-- leaves it INVALID and IF NOT EXISTS skips it on the retry: drop it (DROP INDEX security.idx_identity_tenant_id_created_at) and apply again.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_identity_tenant_id_created_at ON security.identity (tenant_id, created_at DESC, identity_id DESC);
