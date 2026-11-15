-- The emergency access of the Platform Administrator reuses the support access (HU-SEC-007 part B, plan 010 D-01): its basis, the statement of why
-- the authorization of a Tenant Administrator was impossible, and the sensitive data with their own justification. Expand only: every
-- existing row reads as an authorized access and not sensitive.
ALTER TABLE security.support_access
    ADD COLUMN basis            text    NOT NULL DEFAULT 'TENANT_AUTHORIZATION',
    ADD COLUMN statement        text,
    ADD COLUMN sensitive        boolean NOT NULL DEFAULT false,
    ADD COLUMN sensitive_reason text,
    ADD CONSTRAINT chk_support_access_basis CHECK (basis IN ('TENANT_AUTHORIZATION', 'EMERGENCY')),
    ADD CONSTRAINT chk_support_access_emergency_statement CHECK (
        (basis = 'EMERGENCY' AND statement IS NOT NULL AND char_length(statement) BETWEEN 1 AND 500)
        OR (basis = 'TENANT_AUTHORIZATION' AND statement IS NULL)),
    ADD CONSTRAINT chk_support_access_sensitive_reason CHECK (
        (sensitive AND sensitive_reason IS NOT NULL AND char_length(sensitive_reason) BETWEEN 1 AND 500)
        OR (NOT sensitive AND sensitive_reason IS NULL)),
    ADD CONSTRAINT chk_support_access_sensitive_emergency CHECK (NOT sensitive OR basis = 'EMERGENCY'),
    ADD CONSTRAINT chk_support_access_emergency_decider CHECK (basis <> 'EMERGENCY' OR decided_by IS NULL);
