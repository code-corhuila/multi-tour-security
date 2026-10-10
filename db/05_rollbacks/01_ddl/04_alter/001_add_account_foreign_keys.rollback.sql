ALTER TABLE security.refresh_token DROP CONSTRAINT IF EXISTS fk_refresh_token_session;
ALTER TABLE security.session DROP CONSTRAINT IF EXISTS fk_session_identity;
ALTER TABLE security.membership_role DROP CONSTRAINT IF EXISTS fk_membership_role_membership;
ALTER TABLE security.membership DROP CONSTRAINT IF EXISTS fk_membership_identity;
