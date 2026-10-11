-- Serves the foreign key of the key table (the primary key already serves the lookup by scope and key)
CREATE INDEX idx_idempotency_key_identity_id ON security.idempotency_key (identity_id);
