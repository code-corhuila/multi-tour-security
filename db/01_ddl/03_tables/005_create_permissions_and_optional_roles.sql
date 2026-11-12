-- The special permissions of a user and the optional roles of a tenant (HU-SEC-006, plan D-03 and D-04). A permission belongs
-- to the membership, as the roles do, and is held while it has no removal; the row keeps who and when of its last grant and
-- removal, so the trace stays with the user when the outbox purges its events. The foreign key is in 04_alter.
CREATE TABLE security.membership_permission (
    membership_id uuid        NOT NULL,
    permission    text        NOT NULL,
    granted_at    timestamptz NOT NULL,
    granted_by    text        NOT NULL,
    revoked_at    timestamptz,
    revoked_by    text,
    CONSTRAINT pk_membership_permission PRIMARY KEY (membership_id, permission),
    CONSTRAINT chk_membership_permission_permission CHECK (permission IN (
        'VALIDATE_PAYMENT_PROOFS', 'MANAGE_CASH', 'MANAGE_DEPARTURE_EXECUTION', 'CONSULT_SENSITIVE_DATA')),
    CONSTRAINT chk_membership_permission_granted_by CHECK (char_length(granted_by) BETWEEN 1 AND 100),
    CONSTRAINT chk_membership_permission_revoked_by CHECK (revoked_by IS NULL OR char_length(revoked_by) BETWEEN 1 AND 100),
    CONSTRAINT chk_membership_permission_revoked_trace CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

-- An optional role is enabled for a tenant when its row says so; a missing row is a role not enabled, so a tenant starts with
-- none. tenant_id is a reference to identity-audit, never a foreign key (Annex J, J.3.4).
CREATE TABLE security.tenant_optional_role (
    tenant_id  uuid        NOT NULL,
    role       text        NOT NULL,
    enabled    boolean     NOT NULL,
    changed_at timestamptz NOT NULL,
    changed_by text        NOT NULL,
    CONSTRAINT pk_tenant_optional_role PRIMARY KEY (tenant_id, role),
    CONSTRAINT chk_tenant_optional_role_role CHECK (role IN ('MANAGER', 'ACCOUNTANT', 'ANALYST')),
    CONSTRAINT chk_tenant_optional_role_changed_by CHECK (char_length(changed_by) BETWEEN 1 AND 100)
);
