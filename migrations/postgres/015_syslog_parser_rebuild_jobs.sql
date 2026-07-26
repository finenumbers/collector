CREATE TABLE IF NOT EXISTS syslog_parser_rebuild_jobs (
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  parser_version text NOT NULL,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'paused', 'completed', 'failed')),
  cursor_received_us bigint NOT NULL DEFAULT 0,
  cursor_event_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
  watermark_received_us bigint NOT NULL,
  watermark_event_id uuid NOT NULL,
  total_events bigint NOT NULL DEFAULT 0 CHECK (total_events >= 0),
  processed_events bigint NOT NULL DEFAULT 0 CHECK (processed_events >= 0),
  processed_batches bigint NOT NULL DEFAULT 0 CHECK (processed_batches >= 0),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_batch_events integer NOT NULL DEFAULT 0 CHECK (last_batch_events >= 0),
  error text,
  heartbeat_at timestamptz,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (device_id, parser_version),
  CHECK (
    (cursor_received_us, cursor_event_id) <=
    (watermark_received_us, watermark_event_id)
  )
);

CREATE INDEX IF NOT EXISTS syslog_parser_rebuild_jobs_queue_idx
  ON syslog_parser_rebuild_jobs (next_attempt_at, updated_at, device_id)
  WHERE status IN ('pending', 'running');
