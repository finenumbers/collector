ALTER TABLE collector.custom_antifraud_calls
    ADD COLUMN IF NOT EXISTS disconnect_cause_q850 Nullable(Int64) DEFAULT NULL;

ALTER TABLE collector.custom_antifraud_calls
    ADD COLUMN IF NOT EXISTS delay_time_sec Nullable(Int64) DEFAULT NULL;

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
