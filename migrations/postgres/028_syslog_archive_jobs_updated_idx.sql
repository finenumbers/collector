CREATE INDEX IF NOT EXISTS syslog_archive_jobs_updated_idx
  ON syslog_archive_jobs (updated_at DESC, id DESC);
