ALTER TABLE custom_projection_jobs
  ADD COLUMN IF NOT EXISTS generation bigint NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS claimed_generation bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS cutoff_at timestamptz;

CREATE TABLE IF NOT EXISTS custom_reconciliation_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  policy_revision bigint NOT NULL,
  kind text NOT NULL CHECK (kind IN ('discover', 'bucket')),
  bucket_start timestamptz,
  cursor_event_at timestamptz,
  cursor_record_id uuid,
  generation bigint NOT NULL DEFAULT 1,
  claimed_generation bigint NOT NULL DEFAULT 0,
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

CREATE UNIQUE INDEX IF NOT EXISTS custom_reconciliation_job_identity_idx
  ON custom_reconciliation_jobs
    (device_id, policy_revision, kind, COALESCE(bucket_start, '-infinity'::timestamptz));
CREATE INDEX IF NOT EXISTS custom_reconciliation_job_claim_idx
  ON custom_reconciliation_jobs (next_attempt_at, updated_at, device_id)
  WHERE status IN ('pending', 'running');

CREATE TABLE IF NOT EXISTS custom_reconciliation_device_leases (
  device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  worker_id text NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO custom_reconciliation_jobs (device_id, policy_revision, kind)
SELECT id, antifraud_policy_revision, 'discover'
FROM devices
WHERE antifraud_enabled
ON CONFLICT DO NOTHING;
