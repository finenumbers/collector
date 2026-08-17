CREATE TABLE IF NOT EXISTS syslog_archive_worker (
  k smallint PRIMARY KEY DEFAULT 1 CHECK (k = 1),
  worker_id text NOT NULL DEFAULT '',
  heartbeat_at timestamptz,
  last_tick_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO syslog_archive_worker (k) VALUES (1)
ON CONFLICT (k) DO NOTHING;
