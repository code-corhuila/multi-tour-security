-- Only what the migration wrote: a role an Administrator enabled or disabled afterwards carries their name and stays
DELETE FROM security.tenant_optional_role WHERE changed_by = 'migration/security-dml-002';
