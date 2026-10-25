-- The Final Customer accounts made before HU-SEC-003 were active without a verified e-mail (the declared deviation of
-- HU-SEC-002). They become pending, and each person asks for a link (spec R-4). Only an account of a tenant whose every
-- role is Final Customer, with an ordinary password: internal users, the first Administrator and the Platform
-- Administrator are not verified by e-mail and keep signing in.
UPDATE security.identity i
SET identity_status = 'PENDING'
WHERE i.identity_status = 'ACTIVE'
  AND i.email_verified = false
  AND i.tenant_id IS NOT NULL
  AND i.temporary_until IS NULL
  AND EXISTS (SELECT 1 FROM security.membership m JOIN security.membership_role r USING (membership_id)
              WHERE m.identity_id = i.identity_id AND r.role = 'FINAL_CUSTOMER')
  AND NOT EXISTS (SELECT 1 FROM security.membership m JOIN security.membership_role r USING (membership_id)
                  WHERE m.identity_id = i.identity_id AND r.role <> 'FINAL_CUSTOMER');
