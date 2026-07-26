ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS parser_template text;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS parser_version text;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_state text;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_template text;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_version text;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_requested_at timestamptz;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_started_at timestamptz;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_completed_at timestamptz;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_attempts integer;
ALTER TABLE ingest_files ADD COLUMN IF NOT EXISTS replay_error text;

UPDATE ingest_files AS f
SET parser_template = d.template_key,
    parser_version = CASE d.template_key
      WHEN 'satel-rtu-cdr-v1' THEN 'satel-rtu-cdr-v1'
      WHEN 'softswitch-cdr-raw-v1' THEN 'raw-archive-v1'
      ELSE 'eltex-cdr-v1'
    END
FROM devices AS d
WHERE d.id = f.device_id
  AND (f.parser_template IS NULL OR f.parser_version IS NULL);

UPDATE ingest_files
SET parser_template = COALESCE(parser_template, ''),
    parser_version = COALESCE(parser_version, ''),
    replay_state = COALESCE(replay_state, 'none'),
    replay_attempts = COALESCE(replay_attempts, 0);

ALTER TABLE ingest_files ALTER COLUMN parser_template SET DEFAULT '';
ALTER TABLE ingest_files ALTER COLUMN parser_version SET DEFAULT '';
ALTER TABLE ingest_files ALTER COLUMN replay_state SET DEFAULT 'none';
ALTER TABLE ingest_files ALTER COLUMN replay_attempts SET DEFAULT 0;
ALTER TABLE ingest_files ALTER COLUMN parser_template SET NOT NULL;
ALTER TABLE ingest_files ALTER COLUMN parser_version SET NOT NULL;
ALTER TABLE ingest_files ALTER COLUMN replay_state SET NOT NULL;
ALTER TABLE ingest_files ALTER COLUMN replay_attempts SET NOT NULL;

ALTER TABLE ingest_files DROP CONSTRAINT IF EXISTS ingest_files_replay_state_check;
ALTER TABLE ingest_files ADD CONSTRAINT ingest_files_replay_state_check
  CHECK (replay_state IN ('none', 'pending', 'processing', 'complete'));

CREATE INDEX IF NOT EXISTS ingest_files_replay_queue_idx
  ON ingest_files (replay_requested_at, id)
  WHERE replay_state IN ('pending', 'processing');
