UPDATE devices
SET cdr_source_timezone = timezone,
    timezone_revision = GREATEST(timezone_revision, active_timezone_revision) + 1
WHERE cdr_source_timezone IS DISTINCT FROM timezone;

ALTER TABLE devices
    ALTER COLUMN cdr_source_timezone DROP DEFAULT;
