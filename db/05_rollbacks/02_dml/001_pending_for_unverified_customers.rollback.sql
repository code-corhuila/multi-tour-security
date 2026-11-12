-- Back to the state before the migration; an account that was pending because it was created after HU-SEC-003 returns too,
-- which is the price of undoing the story
UPDATE security.identity SET identity_status = 'ACTIVE' WHERE identity_status = 'PENDING' AND email_verified = false;
