-- The links that verify the e-mail of a Final Customer account (HU-SEC-003, plan D-02, D-03). Only the SHA-256 of the
-- link is kept, never the link. A row is one link: it is valid while it is unused, unreplaced and unexpired, and the
-- rows of an account created in the last hour are what limits the links to three an hour. A failed send is recorded
-- on the row, without the link. The foreign key is in 04_alter.
CREATE TABLE security.email_verification (
    verification_id uuid CONSTRAINT pk_email_verification PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id     uuid        NOT NULL,
    token_hash      text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    used_at         timestamptz,
    replaced_at     timestamptz,
    send_failed_at  timestamptz,
    send_error      text,
    CONSTRAINT chk_email_verification_hash CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_email_verification_expiry CHECK (expires_at > created_at),
    CONSTRAINT chk_email_verification_send_error CHECK (send_error IS NULL OR char_length(send_error) <= 200)
);
