ALTER TABLE devices ADD COLUMN IF NOT EXISTS source_category text;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS template_key text;

UPDATE devices
SET source_category = 'equipment'
WHERE source_category IS NULL;

UPDATE devices
SET template_key = CASE
  WHEN firmware = '3.410' OR firmware LIKE '3.410%' THEN 'eltex-smg-1016m-3.410'
  ELSE 'eltex-smg-1016m-3.23.2'
END
WHERE template_key IS NULL;

-- Earlier migrations intentionally canonicalize every firmware on each startup.
-- Restore harmless legacy placeholders for raw sources; template_key is authoritative.
UPDATE devices
SET model = 'Softswitch', firmware = 'raw'
WHERE template_key = 'softswitch-cdr-raw-v1';

ALTER TABLE devices ALTER COLUMN source_category SET DEFAULT 'equipment';
ALTER TABLE devices ALTER COLUMN template_key SET DEFAULT 'eltex-smg-1016m-3.23.2';
ALTER TABLE devices ALTER COLUMN source_category SET NOT NULL;
ALTER TABLE devices ALTER COLUMN template_key SET NOT NULL;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'devices_source_category_check' AND conrelid = 'devices'::regclass
  ) THEN
    ALTER TABLE devices ADD CONSTRAINT devices_source_category_check
      CHECK (source_category IN ('equipment', 'softswitch'));
  END IF;
END
$$;

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_syslog_source_ip_key;
ALTER TABLE devices ALTER COLUMN syslog_source_ip DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS devices_syslog_source_ip_unique
  ON devices (syslog_source_ip) WHERE syslog_source_ip IS NOT NULL;

ALTER TABLE ingest_files DROP CONSTRAINT IF EXISTS ingest_files_status_check;
ALTER TABLE ingest_files ADD CONSTRAINT ingest_files_status_check
  CHECK (status IN ('received', 'processing', 'processed', 'quarantined', 'failed', 'archived'));
