-- tenant_id is null for the events of the Platform Administrator, who has no tenant (ADR-004 D5).
-- Fields and statuses follow 06-data/modeling-conventions.md; status values other than PENDING
-- are PROPUESTO there (ADR-004 D4). No foreign key leaves the schema (Annex J, J.3.4).
CREATE TABLE security.outbox_event (
    outbox_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid,
    event_type      text        NOT NULL,
    event_version   integer     NOT NULL DEFAULT 1,
    aggregate_id    uuid        NOT NULL,
    actor_id        uuid,
    reason          text,
    payload         jsonb       NOT NULL,
    correlation_id  text        NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    published_at    timestamptz,
    status          text        NOT NULL DEFAULT 'PENDING',
    attempts        integer     NOT NULL DEFAULT 0,
    last_error      text,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_outbox_event_status CHECK (status IN ('PENDING', 'PUBLISHED', 'FAILED')),
    CONSTRAINT chk_outbox_event_event_type CHECK (char_length(event_type) BETWEEN 1 AND 100),
    CONSTRAINT chk_outbox_event_event_version CHECK (event_version >= 1),
    CONSTRAINT chk_outbox_event_attempts CHECK (attempts >= 0),
    CONSTRAINT chk_outbox_event_reason CHECK (reason IS NULL OR char_length(reason) <= 500),
    CONSTRAINT chk_outbox_event_last_error CHECK (last_error IS NULL OR char_length(last_error) <= 1000),
    CONSTRAINT chk_outbox_event_correlation_id CHECK (char_length(correlation_id) BETWEEN 1 AND 128)
);
