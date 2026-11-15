-- The codes that let a person choose a new password (HU-SEC-004, plan D-02, D-03): the recovery_codes of 06-data, in the
-- singular. Only the HMAC of the code is kept, never the code. A row is one code: it is live while it is unused, not
-- retired and unexpired; a new code retires the earlier ones and the fifth wrong try retires the code. The rows of an
-- account created in the last hour are what limits the codes to three an hour. A failed send is recorded on the row,
-- without the code. The foreign key is in 04_alter.
CREATE TABLE security.recovery_code (
    recovery_id    uuid CONSTRAINT pk_recovery_code PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id    uuid        NOT NULL,
    code_hmac      text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    wrong_tries    integer     NOT NULL DEFAULT 0,
    used_at        timestamptz,
    retired_at     timestamptz,
    send_failed_at timestamptz,
    send_error     text,
    CONSTRAINT chk_recovery_code_hmac CHECK (code_hmac ~ '^[0-9a-f]{64}$'),
    CONSTRAINT chk_recovery_code_expiry CHECK (expires_at > created_at),
    CONSTRAINT chk_recovery_code_wrong_tries CHECK (wrong_tries BETWEEN 0 AND 5),
    CONSTRAINT chk_recovery_code_send_error CHECK (send_error IS NULL OR char_length(send_error) <= 200)
);
