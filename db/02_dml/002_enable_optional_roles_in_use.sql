-- The tenants that already have users with an optional role, registered before HU-SEC-006, start with that role enabled, so
-- that nobody is left in a role their tenant does not have (spec RN-SEC-005-15, plan D-04). An inactive user counts too: they can
-- be reactivated into a role that exists. No person acted, so no event is written.
INSERT INTO security.tenant_optional_role (tenant_id, role, enabled, changed_at, changed_by)
SELECT DISTINCT i.tenant_id, r.role, true, now(), 'migration/security-dml-002'
FROM security.identity i
JOIN security.membership m USING (identity_id)
JOIN security.membership_role r USING (membership_id)
WHERE i.tenant_id IS NOT NULL AND r.role IN ('MANAGER', 'ACCOUNTANT', 'ANALYST')
ON CONFLICT (tenant_id, role) DO NOTHING;
