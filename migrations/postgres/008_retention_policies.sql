CREATE TABLE IF NOT EXISTS retention_policies (
  policy_class text PRIMARY KEY
    CHECK (policy_class IN ('syslog', 'cdr', 'derived', 'raw_cdr_archive')),
  active_days integer NOT NULL DEFAULT 1095 CHECK (active_days BETWEEN 7 AND 1095),
  pending_days integer CHECK (pending_days BETWEEN 7 AND 1095),
  effective_at timestamptz,
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  last_applied_at timestamptz,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((pending_days IS NULL) = (effective_at IS NULL))
);

INSERT INTO retention_policies (policy_class, active_days, pending_days, effective_at)
VALUES
  ('syslog', 1095, 1095, now()),
  ('cdr', 1095, 1095, now()),
  ('derived', 1095, 1095, now()),
  ('raw_cdr_archive', 1095, 1095, now())
ON CONFLICT (policy_class) DO NOTHING;
