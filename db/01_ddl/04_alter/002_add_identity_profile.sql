-- The profile of an account (HU-SEC-002, plan D-04). Both are optional: the Platform Administrator and the accounts of
-- HU-SEC-001 have none. The name is one text ("first last"); the phone accepts digits, +, spaces, hyphens and parentheses.
ALTER TABLE security.identity
    ADD COLUMN full_name text,
    ADD COLUMN phone     text,
    ADD CONSTRAINT chk_identity_full_name CHECK (full_name IS NULL OR char_length(full_name) BETWEEN 1 AND 100),
    ADD CONSTRAINT chk_identity_phone CHECK (phone IS NULL OR phone ~ '^[0-9+() -]{7,20}$');
