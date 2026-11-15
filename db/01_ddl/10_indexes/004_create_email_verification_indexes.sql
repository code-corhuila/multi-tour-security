-- The link is found by its hash; the links of an account are counted by their creation time (HU-SEC-003, plan D-03)
CREATE UNIQUE INDEX idx_email_verification_token_hash ON security.email_verification (token_hash);
CREATE INDEX idx_email_verification_identity_created_at ON security.email_verification (identity_id, created_at);
