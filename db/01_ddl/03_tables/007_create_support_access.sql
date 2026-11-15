-- The support access of the Platform Administrator, authorized by a Tenant Administrator (HU-SEC-007 part A, plan D-01): a request with its
-- life (pending, approved, over). tenant_id is a reference to identity-audit and never a foreign key (Annex J, J.3.4). The foreign keys to
-- the accounts are in 04_alter. The areas are a closed list that never includes the sensitive data. A request is idempotent by the key its
-- author sent (RN-SEC-009-09).
CREATE TABLE security.support_access (
    support_access_id uuid CONSTRAINT pk_support_access PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid        NOT NULL,
    requested_by      uuid        NOT NULL,
    request_key       text        NOT NULL,
    reason            text        NOT NULL,
    areas             text[]      NOT NULL,
    hours             integer     NOT NULL,
    status            text        NOT NULL DEFAULT 'PENDING',
    requested_at      timestamptz NOT NULL,
    decided_by        uuid,
    decided_at        timestamptz,
    decision_reason   text,
    expires_at        timestamptz,
    opened_at         timestamptz,
    closed_at         timestamptz,
    closed_reason     text,
    CONSTRAINT uq_support_access_request_key UNIQUE (requested_by, request_key),
    CONSTRAINT chk_support_access_key CHECK (char_length(request_key) BETWEEN 8 AND 128),
    CONSTRAINT chk_support_access_reason CHECK (char_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT chk_support_access_areas CHECK (cardinality(areas) BETWEEN 1 AND 5
        AND areas <@ ARRAY['RESERVATIONS', 'CATALOG', 'OPERATIONS', 'CASH', 'CUSTOMERS']::text[]),
    CONSTRAINT chk_support_access_hours CHECK (hours BETWEEN 1 AND 24),
    CONSTRAINT chk_support_access_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'CLOSED')),
    CONSTRAINT chk_support_access_decision_reason CHECK (decision_reason IS NULL OR char_length(decision_reason) BETWEEN 1 AND 500),
    CONSTRAINT chk_support_access_closed_reason CHECK (closed_reason IS NULL OR char_length(closed_reason) BETWEEN 1 AND 500),
    CONSTRAINT chk_support_access_window CHECK (expires_at IS NULL OR decided_at IS NULL OR expires_at > decided_at)
);
