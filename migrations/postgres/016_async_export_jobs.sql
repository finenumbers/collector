ALTER TABLE export_jobs DROP CONSTRAINT IF EXISTS export_jobs_status_check;
ALTER TABLE export_jobs DROP CONSTRAINT IF EXISTS export_jobs_device_id_fkey;
ALTER TABLE export_jobs DROP CONSTRAINT IF EXISTS export_jobs_format_check;

DELETE FROM export_jobs WHERE device_id IS NULL;

ALTER TABLE export_jobs
  ALTER COLUMN device_id SET NOT NULL,
  ADD COLUMN IF NOT EXISTS category text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS search text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS range_from timestamptz,
  ADD COLUMN IF NOT EXISTS range_to timestamptz,
  ADD COLUMN IF NOT EXISTS format text NOT NULL DEFAULT 'auto',
  ADD COLUMN IF NOT EXISTS output_format text,
  ADD COLUMN IF NOT EXISTS filename text,
  ADD COLUMN IF NOT EXISTS content_type text,
  ADD COLUMN IF NOT EXISTS size_bytes bigint,
  ADD COLUMN IF NOT EXISTS sha256 text,
  ADD COLUMN IF NOT EXISTS rows_estimated bigint,
  ADD COLUMN IF NOT EXISTS rows_processed bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS bytes_spooled bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS active_revision bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT 'UTC',
  ADD COLUMN IF NOT EXISTS template_key text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS parser_version text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS raw_high_watermark timestamptz,
  ADD COLUMN IF NOT EXISTS raw_high_watermark_id uuid,
  ADD COLUMN IF NOT EXISTS cancel_requested_at timestamptz,
  ADD COLUMN IF NOT EXISTS started_at timestamptz,
  ADD COLUMN IF NOT EXISTS heartbeat_at timestamptz,
  ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz,
  ADD COLUMN IF NOT EXISTS worker_id text,
  ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE export_jobs ADD CONSTRAINT export_jobs_device_id_fkey
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;

UPDATE export_jobs
SET status='failed', error='legacy export job cannot be resumed', finished_at=now(),
    expires_at=COALESCE(expires_at, now()+interval '7 days')
WHERE status IN ('queued','running') AND template_key='';

ALTER TABLE export_jobs ADD CONSTRAINT export_jobs_status_check
  CHECK (status IN ('queued','running','completed','failed','cancelled','expired'));
ALTER TABLE export_jobs ADD CONSTRAINT export_jobs_format_check
  CHECK (format IN ('auto','xlsx','csv_zip'));

CREATE INDEX IF NOT EXISTS export_jobs_claim_idx
  ON export_jobs (created_at, id)
  WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS export_jobs_device_page_idx
  ON export_jobs (device_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS export_jobs_expiry_idx
  ON export_jobs (expires_at)
  WHERE status IN ('completed','failed','cancelled');
