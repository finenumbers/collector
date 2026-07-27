CREATE TABLE IF NOT EXISTS collector.cdr_voipmonitor_links
(
    device_id UUID,
    event_month Date,
    source_system LowCardinality(String),
    source_record_id UUID,
    source_cdr_id String,
    source_call_id String,
    source_protocol_conf_id String,
    source_call_id_out_proto String,
    policy_revision UInt64,
    projection_seq UInt64,
    voipmonitor_cdr_id String,
    voipmonitor_call_id String,
    voipmonitor_card_url String,
    match_method LowCardinality(String),
    match_score UInt8,
    match_status LowCardinality(String),
    match_evidence_json String,
    matched_at Nullable(DateTime64(6, 'UTC')),
    updated_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(event_month)
ORDER BY (device_id, source_system, source_record_id, policy_revision);

CREATE TABLE IF NOT EXISTS collector.voipmonitor_dirty_buckets
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    policy_revision UInt64,
    projection_seq UInt64,
    reason LowCardinality(String),
    enqueued_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(bucket_start)
ORDER BY (device_id, bucket_start, policy_revision);

CREATE OR REPLACE VIEW collector.cdr_voipmonitor_links_current AS
SELECT *
FROM
(
    SELECT
        *,
        row_number() OVER (
            PARTITION BY device_id, source_system, source_record_id, policy_revision
            ORDER BY projection_seq DESC
        ) AS rn
    FROM collector.cdr_voipmonitor_links FINAL
)
WHERE rn = 1 AND deleted = 0;
