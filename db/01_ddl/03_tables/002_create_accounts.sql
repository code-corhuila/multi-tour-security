-- The accounts of the security microservice (ADR-004 D5, ADR-005 E1, 06-data "Identity and access"). No foreign key
-- here: they are in 04_alter. tenant_id is a reference to identity-audit and never a foreign key (Annex J, J.3.4); it is
-- null only for the Platform Administrator (a membership has no tenant of its own: it is the one of its account).
-- That a role fits the tenant (the platform role only with no tenant) is a rule of the adapter. The password is a bcrypt hash, never a password (RN-SEC-M-08).
CREATE TABLE security.identity (
    identity_id           uuid CONSTRAINT pk_identity PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid,
    email_normalized      text        NOT NULL,
    password_hash         text        NOT NULL,
    identity_status       text        NOT NULL DEFAULT 'ACTIVE',
    email_verified        boolean     NOT NULL DEFAULT false,
    temporary_until       timestamptz,
    failed_count          integer     NOT NULL DEFAULT 0,
    first_failed_at       timestamptz,
    blocked_until         timestamptz,
    sessions_revoked_from timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    -- NULLS NOT DISTINCT: the accounts of the platform have no tenant and still cannot repeat an e-mail
    CONSTRAINT uq_identity_tenant_email UNIQUE NULLS NOT DISTINCT (tenant_id, email_normalized),
    CONSTRAINT chk_identity_email CHECK (char_length(email_normalized) BETWEEN 3 AND 254 AND email_normalized = lower(email_normalized)),
    CONSTRAINT chk_identity_password_hash CHECK (password_hash ~ '^\$2[aby]\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$'),
    CONSTRAINT chk_identity_status CHECK (identity_status IN ('ACTIVE', 'INACTIVE')),
    CONSTRAINT chk_identity_failed_count CHECK (failed_count >= 0)
);

CREATE TABLE security.membership (
    membership_id     uuid CONSTRAINT pk_membership PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id       uuid        NOT NULL,
    membership_status text        NOT NULL DEFAULT 'ACTIVE',
    created_at        timestamptz NOT NULL DEFAULT now(),
    created_by        text        NOT NULL,
    CONSTRAINT uq_membership_identity UNIQUE (identity_id),
    CONSTRAINT chk_membership_status CHECK (membership_status IN ('ACTIVE', 'INACTIVE')),
    CONSTRAINT chk_membership_created_by CHECK (char_length(created_by) BETWEEN 1 AND 100)
);

CREATE TABLE security.membership_role (
    membership_id uuid NOT NULL,
    role          text NOT NULL,
    CONSTRAINT pk_membership_role PRIMARY KEY (membership_id, role),
    CONSTRAINT chk_membership_role_role CHECK (role IN (
        'FINAL_CUSTOMER', 'TENANT_ADMINISTRATOR', 'OPERATIONAL_COLLABORATOR', 'MANAGER', 'ACCOUNTANT', 'ANALYST',
        'PLATFORM_ADMINISTRATOR'))
);

-- A session lasts at most 7 days; the renewal values are kept only as a SHA-256 hash and each works once
CREATE TABLE security.session (
    session_id  uuid CONSTRAINT pk_session PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    CONSTRAINT chk_session_expires CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days')
);

CREATE TABLE security.refresh_token (
    token_hash  text CONSTRAINT pk_refresh_token PRIMARY KEY,
    session_id  uuid        NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT chk_refresh_token_hash CHECK (token_hash ~ '^[0-9a-f]{64}$')
);

-- What this service knows of each tenant from the events of identity-audit (ADR-004 D5)
CREATE TABLE security.tenant_copy (
    tenant_id   uuid CONSTRAINT pk_tenant_copy PRIMARY KEY,
    identifier  text        NOT NULL,
    status      text        NOT NULL,
    occurred_at timestamptz NOT NULL,
    CONSTRAINT uq_tenant_copy_identifier UNIQUE (identifier),
    CONSTRAINT chk_tenant_copy_status CHECK (status IN ('PENDING', 'ACTIVE', 'INACTIVE', 'FAILED')),
    CONSTRAINT chk_tenant_copy_identifier CHECK (char_length(identifier) BETWEEN 3 AND 40)
);
