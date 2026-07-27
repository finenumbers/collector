-- ClickHouse expands SELECT * in views at CREATE time. After 027 added
-- acct_session_ids to the table, recreate the current view so list/detail
-- queries can read the new column.
ALTER TABLE collector.custom_antifraud_calls
    ADD COLUMN IF NOT EXISTS acct_session_ids Array(String) DEFAULT [];

DROP VIEW IF EXISTS collector.custom_antifraud_calls_current;

CREATE VIEW collector.custom_antifraud_calls_current AS
SELECT call.*
FROM (SELECT * FROM collector.custom_antifraud_calls FINAL) AS call
INNER JOIN
(
    SELECT device_id, bucket_start, argMax(snapshot_id, projection_seq) AS snapshot_id,
           argMax(marker, projection_seq) AS marker
    FROM collector.custom_projection_state
    GROUP BY device_id, bucket_start
) AS state USING (device_id, bucket_start, snapshot_id)
WHERE call.deleted = 0 AND state.marker = 'active'
