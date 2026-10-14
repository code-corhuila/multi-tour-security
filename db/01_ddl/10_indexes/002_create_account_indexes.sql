-- The indexes that serve the foreign keys of the accounts and the purge by expiry (ADR-004 D10)
CREATE INDEX idx_session_identity_id ON security.session (identity_id);
CREATE INDEX idx_refresh_token_session_id ON security.refresh_token (session_id);
CREATE INDEX idx_session_expires_at ON security.session (expires_at);
CREATE INDEX idx_refresh_token_expires_at ON security.refresh_token (expires_at);
