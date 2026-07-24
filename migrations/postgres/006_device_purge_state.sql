ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS purge_state text NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS purge_error text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS purge_updated_at timestamptz NOT NULL DEFAULT now();

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_purge_state_check;
ALTER TABLE devices
  ADD CONSTRAINT devices_purge_state_check
  CHECK (purge_state IN ('active', 'deleting', 'purge_failed'));
