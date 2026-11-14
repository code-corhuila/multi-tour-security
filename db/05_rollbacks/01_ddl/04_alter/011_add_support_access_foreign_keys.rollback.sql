ALTER TABLE security.support_access
    DROP CONSTRAINT IF EXISTS fk_support_access_decided_by,
    DROP CONSTRAINT IF EXISTS fk_support_access_requested_by;
