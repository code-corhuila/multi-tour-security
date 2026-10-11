ALTER TABLE security.identity DROP CONSTRAINT IF EXISTS chk_identity_phone;
ALTER TABLE security.identity DROP CONSTRAINT IF EXISTS chk_identity_full_name;
ALTER TABLE security.identity DROP COLUMN IF EXISTS phone;
ALTER TABLE security.identity DROP COLUMN IF EXISTS full_name;
