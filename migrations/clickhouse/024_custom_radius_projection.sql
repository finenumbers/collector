CREATE TABLE IF NOT EXISTS collector.custom_radius_packets
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    snapshot_id UUID,
    policy_revision UInt64,
    projection_seq UInt64,
    packet_id UUID,
    first_seen_at DateTime64(6, 'UTC'),
    last_seen_at DateTime64(6, 'UTC'),
    contract_key String,
    acct_session_id String,
    h323_conf_id String,
    family LowCardinality(String),
    radius_type LowCardinality(String),
    direction LowCardinality(String),
    phase LowCardinality(String),
    decision LowCardinality(String),
    confidence LowCardinality(String),
    status LowCardinality(String),
    is_antifraud UInt8,
    request_id Nullable(UUID),
    response_id Nullable(UUID),
    ordered_attributes_json String,
    provenance_json String,
    explanation_codes Array(String),
    warnings_json String,
    orphan_reason LowCardinality(String),
    ambiguity_reason LowCardinality(String),
    deleted UInt8 DEFAULT 0,
    INDEX packet_session_bloom acct_session_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX packet_h323_bloom h323_conf_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(first_seen_at)
ORDER BY (device_id, contract_key, acct_session_id, h323_conf_id, packet_id, snapshot_id);

CREATE TABLE IF NOT EXISTS collector.custom_radius_packet_members
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    snapshot_id UUID,
    policy_revision UInt64,
    projection_seq UInt64,
    packet_id UUID,
    member_order UInt16,
    event_id UUID,
    received_at DateTime64(6, 'UTC'),
    source_ip IPv6,
    source_port UInt16,
    deleted UInt8 DEFAULT 0,
    INDEX member_event_bloom event_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(received_at)
ORDER BY (device_id, packet_id, member_order, snapshot_id);

CREATE TABLE IF NOT EXISTS collector.custom_radius_exchanges
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    snapshot_id UUID,
    policy_revision UInt64,
    projection_seq UInt64,
    exchange_id UUID,
    contract_key String,
    acct_session_id String,
    h323_conf_id String,
    request_id UUID,
    response_id Nullable(UUID),
    attempt_ids Array(UUID),
    status LowCardinality(String),
    decision LowCardinality(String),
    explanation_codes Array(String),
    occurred_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0,
    INDEX exchange_contract_bloom contract_key TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (device_id, contract_key, exchange_id, snapshot_id);

CREATE TABLE IF NOT EXISTS collector.custom_antifraud_calls
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    snapshot_id UUID,
    policy_revision UInt64,
    projection_seq UInt64,
    call_id UUID,
    contract_key String,
    acct_session_id String,
    h323_conf_id String,
    calling String,
    called String,
    status LowCardinality(String),
    coverage_state LowCardinality(String),
    accounting_start Nullable(DateTime64(6, 'UTC')),
    accounting_stop Nullable(DateTime64(6, 'UTC')),
    session_duration_seconds Nullable(Int64),
    ordered_attributes_json String,
    unmatched_provenance_json String,
    orphan_packet_ids Array(UUID),
    explanation_codes Array(String),
    first_seen_at DateTime64(6, 'UTC'),
    last_seen_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0,
    INDEX call_session_bloom acct_session_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX call_h323_bloom h323_conf_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(first_seen_at)
ORDER BY (device_id, contract_key, acct_session_id, h323_conf_id, call_id, snapshot_id);

CREATE TABLE IF NOT EXISTS collector.custom_antifraud_call_packets
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    snapshot_id UUID,
    policy_revision UInt64,
    projection_seq UInt64,
    call_id UUID,
    packet_id UUID,
    packet_order UInt16,
    occurred_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (device_id, call_id, packet_order, packet_id, snapshot_id);

CREATE TABLE IF NOT EXISTS collector.custom_projection_dirty_buckets
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

CREATE TABLE IF NOT EXISTS collector.custom_projection_state
(
    device_id UUID,
    bucket_start DateTime('UTC'),
    policy_revision UInt64,
    projection_seq UInt64,
    snapshot_id UUID,
    previous_snapshot_id Nullable(UUID),
    marker LowCardinality(String),
    watermark_received_at Nullable(DateTime64(6, 'UTC')),
    watermark_event_id Nullable(UUID),
    row_count UInt64,
    activated_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(bucket_start)
ORDER BY (device_id, bucket_start);

CREATE VIEW IF NOT EXISTS collector.custom_radius_packets_current AS
SELECT packet.*
FROM (SELECT * FROM collector.custom_radius_packets FINAL) AS packet
INNER JOIN
(
    SELECT device_id, bucket_start, argMax(snapshot_id, projection_seq) AS snapshot_id,
           argMax(marker, projection_seq) AS marker
    FROM collector.custom_projection_state
    GROUP BY device_id, bucket_start
) AS state USING (device_id, bucket_start, snapshot_id)
WHERE packet.deleted = 0 AND state.marker = 'active';

CREATE VIEW IF NOT EXISTS collector.custom_antifraud_calls_current AS
SELECT call.*
FROM (SELECT * FROM collector.custom_antifraud_calls FINAL) AS call
INNER JOIN
(
    SELECT device_id, bucket_start, argMax(snapshot_id, projection_seq) AS snapshot_id,
           argMax(marker, projection_seq) AS marker
    FROM collector.custom_projection_state
    GROUP BY device_id, bucket_start
) AS state USING (device_id, bucket_start, snapshot_id)
WHERE call.deleted = 0 AND state.marker = 'active';
