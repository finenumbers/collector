-- Force one shadow rebuild for every existing SMG so parser v7,
-- continuation assembly and all dependent AntiFraud links cut over atomically.
UPDATE devices
SET timezone_revision = timezone_revision + 1
WHERE enabled;
