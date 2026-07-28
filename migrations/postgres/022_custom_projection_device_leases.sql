CREATE TABLE IF NOT EXISTS custom_projection_device_leases (
  device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  worker_id text NOT NULL,
  lease_expires_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
