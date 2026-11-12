-- A pending account has no place in the old check, so it goes back to active before the check is restored
UPDATE security.identity SET identity_status = 'ACTIVE' WHERE identity_status = 'PENDING';
ALTER TABLE security.identity
    DROP CONSTRAINT IF EXISTS chk_identity_status,
    ADD CONSTRAINT chk_identity_status CHECK (identity_status IN ('ACTIVE', 'INACTIVE')),
    DROP COLUMN IF EXISTS email_verified_at;
