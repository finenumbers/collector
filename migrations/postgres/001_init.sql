CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
  active boolean NOT NULL DEFAULT true,
  failed_attempts integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash bytea PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_hash bytea NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  user_agent text,
  remote_ip inet
);

CREATE TABLE IF NOT EXISTS devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  model text NOT NULL DEFAULT 'SMG-1016M',
  firmware text NOT NULL DEFAULT '3.410.0.7443',
  timezone text NOT NULL DEFAULT 'Asia/Novosibirsk',
  management_ip inet,
  syslog_source_ip inet NOT NULL UNIQUE,
  device_sign text,
  antifraud_enabled boolean NOT NULL DEFAULT false,
  antifraud_mode text NOT NULL DEFAULT 'OFF'
    CHECK (antifraud_mode IN ('OFF', 'Astarta', 'Intek', 'Custom')),
  ftp_username text NOT NULL UNIQUE,
  ftp_home text NOT NULL UNIQUE,
  cdr_columns jsonb NOT NULL DEFAULT '[]'::jsonb,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ingest_files (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  original_name text NOT NULL,
  object_key text NOT NULL,
  sha256 text NOT NULL,
  size_bytes bigint NOT NULL,
  status text NOT NULL CHECK (status IN ('received', 'processing', 'processed', 'quarantined', 'failed')),
  rows_total bigint NOT NULL DEFAULT 0,
  rows_valid bigint NOT NULL DEFAULT 0,
  error text,
  received_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  UNIQUE (device_id, sha256)
);

CREATE TABLE IF NOT EXISTS export_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  requested_by uuid NOT NULL REFERENCES users(id),
  device_id uuid REFERENCES devices(id) ON DELETE SET NULL,
  dataset text NOT NULL,
  filters jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'expired')),
  object_key text,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  expires_at timestamptz
);

CREATE TABLE IF NOT EXISTS audit_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
  action text NOT NULL,
  resource_type text NOT NULL,
  resource_id text,
  remote_ip inet,
  details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS sessions_user_expiry_idx ON sessions (user_id, expires_at);
CREATE INDEX IF NOT EXISTS audit_log_time_idx ON audit_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS ingest_files_device_time_idx ON ingest_files (device_id, received_at DESC);
