-- Who, when and why an account last changed status, and who and when it was last given a temporary credential
-- (HU-SEC-005, plan D-10; PDR §9 asks the trace to stay with the account). It is kept here and not only in the outbox,
-- whose published events the retention job purges (ADR-004 D10). All nullable: an account that never changed has none.
-- The `*_by` is the actor as `created_by` writes it (`tenant-administrator/<accountId>` or `platform-administrator/<accountId>`).
ALTER TABLE security.identity
    ADD COLUMN status_changed_at   timestamptz,
    ADD COLUMN status_changed_by   text,
    ADD COLUMN status_reason       text,
    ADD COLUMN temporary_issued_at timestamptz,
    ADD COLUMN temporary_issued_by text,
    ADD CONSTRAINT chk_identity_status_changed_by CHECK (status_changed_by IS NULL OR char_length(status_changed_by) BETWEEN 1 AND 100),
    ADD CONSTRAINT chk_identity_status_reason CHECK (status_reason IS NULL OR char_length(status_reason) BETWEEN 1 AND 500),
    ADD CONSTRAINT chk_identity_temporary_issued_by CHECK (temporary_issued_by IS NULL OR char_length(temporary_issued_by) BETWEEN 1 AND 100),
    -- who, when and why of a change go together, and so do who and when of a credential: a half-written trace says nothing
    ADD CONSTRAINT chk_identity_status_trace CHECK ((status_changed_at IS NULL) = (status_changed_by IS NULL) AND (status_changed_at IS NULL) = (status_reason IS NULL)),
    ADD CONSTRAINT chk_identity_temporary_trace CHECK ((temporary_issued_at IS NULL) = (temporary_issued_by IS NULL));
