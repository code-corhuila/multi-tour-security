-- A Final Customer account waits as PENDING until its e-mail is verified (HU-SEC-003, plan D-01). email_verified_at is the
-- moment it was verified; it stays empty for the accounts that never go through the link.
ALTER TABLE security.identity
    ADD COLUMN email_verified_at timestamptz,
    DROP CONSTRAINT chk_identity_status,
    ADD CONSTRAINT chk_identity_status CHECK (identity_status IN ('PENDING', 'ACTIVE', 'INACTIVE'));
