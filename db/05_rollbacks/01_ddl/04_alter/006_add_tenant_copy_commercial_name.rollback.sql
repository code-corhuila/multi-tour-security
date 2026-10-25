ALTER TABLE security.tenant_copy DROP CONSTRAINT IF EXISTS chk_tenant_copy_commercial_name;
ALTER TABLE security.tenant_copy DROP COLUMN IF EXISTS commercial_name;
