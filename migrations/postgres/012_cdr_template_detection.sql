ALTER TABLE devices ADD COLUMN IF NOT EXISTS detection_status text NOT NULL DEFAULT 'not_checked';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS detection_template text NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS detection_fingerprint text NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS detection_error text NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS detection_checked_at timestamptz;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS detection_last_file_at timestamptz;

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_detection_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_detection_status_check
  CHECK (detection_status IN ('not_checked', 'no_samples', 'matched', 'mixed', 'error', 'activated'));

CREATE INDEX IF NOT EXISTS devices_raw_detection_idx
  ON devices (detection_status, detection_checked_at)
  WHERE template_key = 'softswitch-cdr-raw-v1' AND purge_state = 'active';
