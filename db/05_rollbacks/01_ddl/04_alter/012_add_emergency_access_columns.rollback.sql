ALTER TABLE security.support_access
    DROP CONSTRAINT IF EXISTS chk_support_access_emergency_decider,
    DROP CONSTRAINT IF EXISTS chk_support_access_sensitive_emergency,
    DROP CONSTRAINT IF EXISTS chk_support_access_sensitive_reason,
    DROP CONSTRAINT IF EXISTS chk_support_access_emergency_statement,
    DROP CONSTRAINT IF EXISTS chk_support_access_basis,
    DROP COLUMN IF EXISTS sensitive_reason,
    DROP COLUMN IF EXISTS sensitive,
    DROP COLUMN IF EXISTS statement,
    DROP COLUMN IF EXISTS basis;
