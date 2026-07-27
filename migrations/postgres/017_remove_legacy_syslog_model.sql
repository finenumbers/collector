DROP TABLE IF EXISTS syslog_parser_rebuild_jobs;

ALTER TABLE devices
  DROP COLUMN IF EXISTS antifraud_mode;

UPDATE retention_policies AS syslog
SET active_days = LEAST(syslog.active_days, legacy.active_days),
    updated_at = now()
FROM retention_policies AS legacy
WHERE syslog.policy_class = 'syslog'
  AND legacy.policy_class = 'derived';

DELETE FROM retention_policies
WHERE policy_class = 'derived';
