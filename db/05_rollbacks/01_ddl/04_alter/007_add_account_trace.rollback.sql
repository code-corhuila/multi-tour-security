ALTER TABLE security.identity
    DROP CONSTRAINT IF EXISTS chk_identity_temporary_trace,
    DROP CONSTRAINT IF EXISTS chk_identity_status_trace,
    DROP CONSTRAINT IF EXISTS chk_identity_temporary_issued_by,
    DROP CONSTRAINT IF EXISTS chk_identity_status_reason,
    DROP CONSTRAINT IF EXISTS chk_identity_status_changed_by,
    DROP COLUMN IF EXISTS temporary_issued_by,
    DROP COLUMN IF EXISTS temporary_issued_at,
    DROP COLUMN IF EXISTS status_reason,
    DROP COLUMN IF EXISTS status_changed_by,
    DROP COLUMN IF EXISTS status_changed_at;
