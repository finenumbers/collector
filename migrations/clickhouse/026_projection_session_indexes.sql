ALTER TABLE collector.syslog_messages
  ADD INDEX IF NOT EXISTS syslog_payload_ngram payload TYPE ngrambf_v1(3, 4096, 3, 0) GRANULARITY 4;

CREATE TABLE IF NOT EXISTS collector.custom_radius_session_events
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    snapshot_id UUID,
    policy_revision UInt64,
    projection_seq UInt64,
    identity_kind LowCardinality(String),
    identity_value String,
    event_id UUID,
    received_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0,
    INDEX session_identity_bloom identity_value TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX session_event_bloom event_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(received_at)
ORDER BY (device_id, identity_kind, identity_value, event_id, snapshot_id);

CREATE VIEW IF NOT EXISTS collector.custom_radius_packet_members_current AS
SELECT member.*
FROM (SELECT * FROM collector.custom_radius_packet_members FINAL) AS member
INNER JOIN
(
    SELECT device_id, bucket_start, argMax(snapshot_id, projection_seq) AS snapshot_id,
           argMax(marker, projection_seq) AS marker
    FROM collector.custom_projection_state
    GROUP BY device_id, bucket_start
) AS state USING (device_id, bucket_start, snapshot_id)
WHERE member.deleted = 0 AND state.marker = 'active';

CREATE VIEW IF NOT EXISTS collector.custom_radius_exchanges_current AS
SELECT exchange.*
FROM (SELECT * FROM collector.custom_radius_exchanges FINAL) AS exchange
INNER JOIN
(
    SELECT device_id, bucket_start, argMax(snapshot_id, projection_seq) AS snapshot_id,
           argMax(marker, projection_seq) AS marker
    FROM collector.custom_projection_state
    GROUP BY device_id, bucket_start
) AS state USING (device_id, bucket_start, snapshot_id)
WHERE exchange.deleted = 0 AND state.marker = 'active';

CREATE VIEW IF NOT EXISTS collector.custom_antifraud_call_packets_current AS
SELECT link.*
FROM (SELECT * FROM collector.custom_antifraud_call_packets FINAL) AS link
INNER JOIN
(
    SELECT device_id, bucket_start, argMax(snapshot_id, projection_seq) AS snapshot_id,
           argMax(marker, projection_seq) AS marker
    FROM collector.custom_projection_state
    GROUP BY device_id, bucket_start
) AS state USING (device_id, bucket_start, snapshot_id)
WHERE link.deleted = 0 AND state.marker = 'active';

CREATE VIEW IF NOT EXISTS collector.custom_radius_session_events_current AS
SELECT session.*
FROM (SELECT * FROM collector.custom_radius_session_events FINAL) AS session
INNER JOIN
(
    SELECT device_id, bucket_start, argMax(snapshot_id, projection_seq) AS snapshot_id,
           argMax(marker, projection_seq) AS marker
    FROM collector.custom_projection_state
    GROUP BY device_id, bucket_start
) AS state USING (device_id, bucket_start, snapshot_id)
WHERE session.deleted = 0 AND state.marker = 'active';
