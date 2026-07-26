ALTER TABLE retention_policies
  DROP CONSTRAINT IF EXISTS retention_policies_policy_class_check;

ALTER TABLE retention_policies
  ADD CONSTRAINT retention_policies_policy_class_check
  CHECK (policy_class IN ('syslog', 'cdr', 'softswitch_cdr', 'derived', 'raw_cdr_archive'));

INSERT INTO retention_policies (
  policy_class,
  active_days,
  pending_days,
  effective_at
)
SELECT
  'softswitch_cdr',
  active_days,
  active_days,
  now()
FROM retention_policies
WHERE policy_class = 'cdr'
ON CONFLICT (policy_class) DO NOTHING;
