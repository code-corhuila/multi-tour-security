-- The links follow their account when it is deleted (HU-SEC-003, plan D-03), as the idempotency keys do
ALTER TABLE security.email_verification
    ADD CONSTRAINT fk_email_verification_identity FOREIGN KEY (identity_id) REFERENCES security.identity (identity_id) ON DELETE CASCADE;
