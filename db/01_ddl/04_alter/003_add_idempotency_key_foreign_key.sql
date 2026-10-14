-- A key belongs to the account it created and goes with it; its index is in 10_indexes (Annex A)
ALTER TABLE security.idempotency_key
    ADD CONSTRAINT fk_idempotency_key_identity FOREIGN KEY (identity_id) REFERENCES security.identity (identity_id) ON DELETE CASCADE;
