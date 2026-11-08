-- The newest live code of an account is found, and the codes of the last hour are counted, by account and creation time
-- (HU-SEC-004, plan D-03)
CREATE INDEX idx_recovery_code_identity_created_at ON security.recovery_code (identity_id, created_at);
