ALTER TABLE security.session
    DROP CONSTRAINT IF EXISTS chk_session_context,
    DROP COLUMN IF EXISTS context;

ALTER TABLE security.membership_role
    DROP CONSTRAINT IF EXISTS chk_membership_role_status,
    DROP COLUMN IF EXISTS role_status;
