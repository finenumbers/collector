UPDATE retention_policies
SET pending_days = active_days,
    effective_at = now(),
    last_error = NULL,
    updated_at = now()
WHERE policy_class IN ('syslog', 'cdr', 'softswitch_cdr');

INSERT INTO custom_projection_jobs (device_id, policy_revision, kind)
SELECT id, antifraud_policy_revision, 'discover'
FROM devices
WHERE antifraud_enabled
ON CONFLICT DO NOTHING;

UPDATE custom_projection_jobs AS job
SET status = 'pending',
    next_attempt_at = now(),
    lease_expires_at = NULL,
    worker_id = NULL,
    completed_at = NULL,
    updated_at = now()
FROM devices AS device
WHERE job.device_id = device.id
  AND job.kind = 'discover'
  AND job.policy_revision = device.antifraud_policy_revision
  AND device.antifraud_enabled
  AND job.status IN ('completed', 'failed');
