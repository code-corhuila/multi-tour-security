-- A permission follows its membership when it is deleted, as the roles do (HU-SEC-006, plan D-03); the leading column of the
-- primary key is its index
ALTER TABLE security.membership_permission
    ADD CONSTRAINT fk_membership_permission_membership FOREIGN KEY (membership_id) REFERENCES security.membership (membership_id) ON DELETE CASCADE;
