WITH converted AS (
  UPDATE devices
  SET template_key = 'satel-rtu-cdr-v1',
      firmware = 'satel-rtu-cdr-v1',
      active_timezone = timezone,
      active_timezone_revision = timezone_revision,
      detection_status = 'activated',
      detection_template = 'satel-rtu-cdr-v1',
      detection_error = ''
  WHERE template_key = 'softswitch-cdr-raw-v1'
  RETURNING id
)
UPDATE ingest_files AS files
SET replay_state = 'pending',
    replay_template = 'satel-rtu-cdr-v1',
    replay_version = 'satel-rtu-cdr-v1',
    replay_requested_at = now(),
    replay_started_at = NULL,
    replay_completed_at = NULL,
    replay_attempts = 0,
    replay_error = NULL
FROM converted
WHERE files.device_id = converted.id
  AND files.object_key <> ''
  AND files.status IN ('archived', 'processed', 'quarantined');

-- Migration files are intentionally replayable. Earlier firmware normalization must
-- not replace the authoritative Satel template marker on later application starts.
UPDATE devices
SET firmware = 'satel-rtu-cdr-v1'
WHERE template_key = 'satel-rtu-cdr-v1'
  AND firmware IS DISTINCT FROM 'satel-rtu-cdr-v1';

DROP INDEX IF EXISTS devices_raw_detection_idx;
