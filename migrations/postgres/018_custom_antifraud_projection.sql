ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS antifraud_policy_revision bigint NOT NULL DEFAULT 1;

CREATE SEQUENCE IF NOT EXISTS custom_projection_seq;

CREATE TABLE IF NOT EXISTS custom_projection_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  policy_revision bigint NOT NULL,
  projection_seq bigint NOT NULL DEFAULT nextval('custom_projection_seq'),
  kind text NOT NULL CHECK (kind IN ('discover', 'bucket', 'disable')),
  bucket_start timestamptz,
  cursor_received_at timestamptz,
  cursor_event_id uuid,
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'running', 'completed', 'cancelled', 'failed')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_expires_at timestamptz,
  worker_id text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  CHECK ((kind = 'bucket') = (bucket_start IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS custom_projection_job_identity_idx
  ON custom_projection_jobs (device_id, policy_revision, kind, COALESCE(bucket_start, '-infinity'::timestamptz));
CREATE INDEX IF NOT EXISTS custom_projection_job_claim_idx
  ON custom_projection_jobs (next_attempt_at, created_at, device_id)
  WHERE status IN ('pending', 'running');

CREATE TABLE IF NOT EXISTS custom_projection_watermarks (
  device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  policy_revision bigint NOT NULL,
  active_snapshot_id uuid,
  previous_snapshot_id uuid,
  watermark_received_at timestamptz,
  watermark_event_id uuid,
  projection_seq bigint NOT NULL DEFAULT 0,
  state text NOT NULL DEFAULT 'disabled'
    CHECK (state IN ('disabled', 'backfilling', 'active', 'failed')),
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO custom_projection_watermarks (device_id, policy_revision, state)
SELECT id, antifraud_policy_revision,
       CASE WHEN antifraud_enabled THEN 'backfilling' ELSE 'disabled' END
FROM devices
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO custom_projection_jobs (device_id, policy_revision, kind)
SELECT id, antifraud_policy_revision, 'discover'
FROM devices
WHERE antifraud_enabled
ON CONFLICT DO NOTHING;
