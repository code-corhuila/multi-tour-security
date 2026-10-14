-- Foreign keys inside the schema, each with its ON DELETE; their indexes are in 10_indexes (Annex A)
ALTER TABLE security.membership
    ADD CONSTRAINT fk_membership_identity FOREIGN KEY (identity_id) REFERENCES security.identity (identity_id) ON DELETE RESTRICT;
ALTER TABLE security.membership_role
    ADD CONSTRAINT fk_membership_role_membership FOREIGN KEY (membership_id) REFERENCES security.membership (membership_id) ON DELETE CASCADE;
ALTER TABLE security.session
    ADD CONSTRAINT fk_session_identity FOREIGN KEY (identity_id) REFERENCES security.identity (identity_id) ON DELETE RESTRICT;
ALTER TABLE security.refresh_token
    ADD CONSTRAINT fk_refresh_token_session FOREIGN KEY (session_id) REFERENCES security.session (session_id) ON DELETE CASCADE;
