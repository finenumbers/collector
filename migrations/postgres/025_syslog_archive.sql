ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS syslog_archive_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS syslog_archive_remote_dir text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS syslog_archive_jobs (
  id uuid PRIMARY KEY,
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  hour_start timestamptz NOT NULL,
  archive_name text NOT NULL,
  remote_dir text NOT NULL DEFAULT '',
  timezone text NOT NULL DEFAULT 'UTC',
  status text NOT NULL,
  local_path text NOT NULL DEFAULT '',
  bytes bigint NOT NULL DEFAULT 0,
  attempts int NOT NULL DEFAULT 0,
  last_error text NOT NULL DEFAULT '',
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  worker_id text,
  heartbeat_at timestamptz,
  lease_expires_at timestamptz,
  uploaded_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT syslog_archive_jobs_status_check CHECK (status IN (
    'pending','building','ready','uploading','uploaded','failed','abandoned','skipped_stale'
  )),
  CONSTRAINT syslog_archive_jobs_device_hour UNIQUE (device_id, hour_start)
);

CREATE INDEX IF NOT EXISTS syslog_archive_jobs_claim_idx
  ON syslog_archive_jobs (next_attempt_at, created_at, id)
  WHERE status IN ('pending','ready','failed','building','uploading');

CREATE INDEX IF NOT EXISTS syslog_archive_jobs_device_idx
  ON syslog_archive_jobs (device_id, hour_start DESC);
