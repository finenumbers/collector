ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS active_timezone text;

UPDATE devices
SET active_timezone = timezone
WHERE active_timezone IS NULL;

ALTER TABLE devices
  ALTER COLUMN active_timezone SET NOT NULL;

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS timezone_revision bigint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS active_timezone_revision bigint NOT NULL DEFAULT 1;
