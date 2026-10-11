-- The keys of the account creation (HU-SEC-002, plan D-04, D-05): one row per intent, written in the same transaction as the
-- account. scope is customer:<tenantId>, user:<tenantId> or first-admin:<tenantId>, so one key in two tenants or on two
-- routes is two intents. The foreign key is in 04_alter.
CREATE TABLE security.idempotency_key (
    scope           text        NOT NULL,
    idempotency_key text        NOT NULL,
    identity_id     uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_idempotency_key PRIMARY KEY (scope, idempotency_key),
    CONSTRAINT chk_idempotency_key_scope CHECK (char_length(scope) BETWEEN 1 AND 100),
    CONSTRAINT chk_idempotency_key_length CHECK (char_length(idempotency_key) BETWEEN 8 AND 128)
);
