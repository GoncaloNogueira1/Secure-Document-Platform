-- Run once against an existing database created before TOTP columns existed.
-- Example: docker compose exec db psql -U postgres -d docdb -f /path/001_add_totp.sql

ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS two_factor_enabled BOOLEAN DEFAULT FALSE;
UPDATE users SET two_factor_enabled = COALESCE(two_factor_enabled, FALSE);
