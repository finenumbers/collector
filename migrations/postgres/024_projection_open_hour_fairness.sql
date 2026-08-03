-- Open-hour claim fairness (least-recently-claimed) and closed-hour window
-- cursor so catch-up can resume after yielding to live tip.
ALTER TABLE custom_projection_jobs
  ADD COLUMN IF NOT EXISTS last_claimed_at timestamptz,
  ADD COLUMN IF NOT EXISTS window_start timestamptz;

CREATE INDEX IF NOT EXISTS custom_projection_job_open_claim_fairness_idx
  ON custom_projection_jobs (last_claimed_at NULLS FIRST, updated_at, created_at)
  WHERE status IN ('pending', 'running') AND kind = 'bucket';
