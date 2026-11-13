-- A status per role, so one side of a person can be switched off without the other (HU-SEC-008, plan D-01), and the side
-- a session was opened for, so a renewal keeps it (plan D-02). A null context is a session of an account with one side.
ALTER TABLE security.membership_role
    ADD COLUMN role_status text NOT NULL DEFAULT 'ACTIVE',
    ADD CONSTRAINT chk_membership_role_status CHECK (role_status IN ('ACTIVE', 'INACTIVE'));

ALTER TABLE security.session
    ADD COLUMN context text,
    ADD CONSTRAINT chk_session_context CHECK (context IS NULL OR context IN ('CUSTOMER', 'TEAM'));
