ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS voipmonitor_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS voipmonitor_policy_revision bigint NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS voipmonitor_match_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  policy_revision bigint NOT NULL,
  kind text NOT NULL CHECK (kind IN ('discover', 'bucket')),
  bucket_start timestamptz,
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

CREATE UNIQUE INDEX IF NOT EXISTS voipmonitor_match_jobs_identity_uidx
  ON voipmonitor_match_jobs (
    device_id, policy_revision, kind, COALESCE(bucket_start, '-infinity'::timestamptz)
  );

CREATE INDEX IF NOT EXISTS voipmonitor_match_jobs_claim_idx
  ON voipmonitor_match_jobs (next_attempt_at, updated_at, device_id)
  WHERE status IN ('pending', 'running');

CREATE TABLE IF NOT EXISTS voipmonitor_device_leases (
  device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  worker_id text NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO voipmonitor_match_jobs (device_id, policy_revision, kind)
SELECT id, voipmonitor_policy_revision, 'discover'
FROM devices WHERE voipmonitor_enabled
ON CONFLICT DO NOTHING;
