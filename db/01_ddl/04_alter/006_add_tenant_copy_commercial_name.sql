-- The visible name of the sender of the e-mail is the commercial name of the tenant (ADR-004 D3, HU-SEC-003 plan D-12).
-- It comes in the TenantCreated event; a copy made before it has none and the e-mail is sent as Multitour.
ALTER TABLE security.tenant_copy
    ADD COLUMN commercial_name text,
    ADD CONSTRAINT chk_tenant_copy_commercial_name CHECK (commercial_name IS NULL OR char_length(commercial_name) BETWEEN 1 AND 100);
