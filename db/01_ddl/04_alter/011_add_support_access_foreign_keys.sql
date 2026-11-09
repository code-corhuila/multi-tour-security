-- Who asked and who decided are accounts, and an account with support accesses is never deleted: the audit of an access outlives its people
-- (HU-SEC-007, plan D-01)
ALTER TABLE security.support_access
    ADD CONSTRAINT fk_support_access_requested_by FOREIGN KEY (requested_by) REFERENCES security.identity (identity_id) ON DELETE RESTRICT,
    ADD CONSTRAINT fk_support_access_decided_by FOREIGN KEY (decided_by) REFERENCES security.identity (identity_id) ON DELETE RESTRICT;
