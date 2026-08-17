ALTER TABLE syslog_archive_jobs
  ADD COLUMN IF NOT EXISTS payload_count bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS max_received_at timestamptz,
  ADD COLUMN IF NOT EXISTS max_event_id uuid;

-- Hourly ZIP jobs that never uploaded would block 10-minute slot HH:00.
DELETE FROM syslog_archive_jobs
WHERE archive_name ~ '_[0-9]{2}\.zip$'
  AND archive_name !~ '_[0-9]{2}-[0-9]{2}\.zip$'
  AND status <> 'uploaded';

CREATE TABLE IF NOT EXISTS syslog_raw_gc (
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  hour_start_utc timestamptz NOT NULL,
  sealed_at timestamptz,
  raw_deleted_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, hour_start_utc)
);

CREATE INDEX IF NOT EXISTS syslog_raw_gc_pending_idx
  ON syslog_raw_gc (hour_start_utc)
  WHERE raw_deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS syslog_raw_history_cutoff (
  k smallint PRIMARY KEY DEFAULT 1 CHECK (k = 1),
  cutoff timestamptz NOT NULL
);

ALTER TABLE retention_policies
  DROP CONSTRAINT IF EXISTS retention_policies_policy_class_check;

UPDATE retention_policies
SET policy_class = 'antifraud', updated_at = now()
WHERE policy_class = 'syslog';

ALTER TABLE retention_policies
  ADD CONSTRAINT retention_policies_policy_class_check
  CHECK (policy_class IN ('antifraud', 'cdr', 'softswitch_cdr', 'raw_cdr_archive'));
