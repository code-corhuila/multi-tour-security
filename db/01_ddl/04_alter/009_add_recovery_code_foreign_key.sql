-- The codes follow their account when it is deleted (HU-SEC-004, plan D-03), as the links and the keys do
ALTER TABLE security.recovery_code
    ADD CONSTRAINT fk_recovery_code_identity FOREIGN KEY (identity_id) REFERENCES security.identity (identity_id) ON DELETE CASCADE;
