ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS cdr_source_timezone text;

UPDATE devices
SET cdr_source_timezone = 'UTC',
    timezone_revision = GREATEST(timezone_revision, active_timezone_revision) + 1
WHERE cdr_source_timezone IS NULL;

ALTER TABLE devices
    ALTER COLUMN cdr_source_timezone SET DEFAULT 'UTC';

ALTER TABLE devices
    ALTER COLUMN cdr_source_timezone SET NOT NULL;
