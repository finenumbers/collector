CREATE TABLE IF NOT EXISTS collector.device_derived_revisions
(
    device_id UUID,
    revision UInt64,
    timezone LowCardinality(String),
    status LowCardinality(String),
    cursor_received_at DateTime64(6, 'UTC'),
    cursor_event_id UUID,
    cdr_cursor_ingested_at DateTime64(6, 'UTC'),
    cdr_cursor_record_id UUID,
    high_watermark DateTime64(6, 'UTC'),
    cdr_high_watermark DateTime64(6, 'UTC'),
    raw_total UInt64,
    cdr_total UInt64,
    processed UInt64,
    cdr_processed UInt64,
    lifecycle_count UInt64,
    error String,
    updated_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (device_id, revision);

CREATE TABLE IF NOT EXISTS collector.syslog_facts
(
    device_id UUID,
    timezone_revision UInt64,
    event_id UUID,
    interpreted_at DateTime64(6, 'UTC'),
    received_at DateTime64(6, 'UTC'),
    raw_wall_clock String,
    event_time_utc Nullable(DateTime64(6, 'UTC')),
    source_timezone LowCardinality(String),
    source_utc_offset_minutes Int16,
    parse_status LowCardinality(String),
    category LowCardinality(String),
    component LowCardinality(String),
    message String,
    attributes Map(String, String)
)
ENGINE = ReplacingMergeTree(interpreted_at)
PARTITION BY toYYYYMM(received_at)
ORDER BY (device_id, timezone_revision, event_id)
TTL toDateTime(received_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.cdr_time_facts
(
    device_id UUID,
    timezone_revision UInt64,
    record_id UUID,
    interpreted_at DateTime64(6, 'UTC'),
    setup_wall_clock String,
    connect_wall_clock String,
    disconnect_wall_clock String,
    setup_time_utc Nullable(DateTime64(6, 'UTC')),
    connect_time_utc Nullable(DateTime64(6, 'UTC')),
    disconnect_time_utc Nullable(DateTime64(6, 'UTC')),
    source_timezone LowCardinality(String),
    source_utc_offset_minutes Int16
)
ENGINE = ReplacingMergeTree(interpreted_at)
ORDER BY (device_id, timezone_revision, record_id);

CREATE TABLE IF NOT EXISTS collector.radius_fragments
(
    device_id UUID,
    timezone_revision UInt64,
    event_id UUID,
    transaction_id UUID,
    packet_transaction_id UUID,
    occurred_at DateTime64(6, 'UTC'),
    call_context String,
    acct_session_id String,
    packet_identifier Nullable(UInt8),
    request_type LowCardinality(String),
    packet_code LowCardinality(String),
    result LowCardinality(String),
    is_antifraud UInt8,
    attributes Map(String, String),
    inserted_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(inserted_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (device_id, timezone_revision, event_id);

CREATE TABLE IF NOT EXISTS collector.antifraud_lifecycles
(
    device_id UUID,
    timezone_revision UInt64,
    transaction_id UUID,
    occurrence UInt32,
    updated_at DateTime64(6, 'UTC'),
    first_event_at DateTime64(6, 'UTC'),
    last_event_at DateTime64(6, 'UTC'),
    call_context String,
    acct_session_id String,
    acct_session_id_normalized String,
    request_type LowCardinality(String),
    request_code LowCardinality(String),
    response_code LowCardinality(String),
    decision LowCardinality(String),
    decision_reason String,
    server_address String,
    retries UInt16,
    latency_ms Nullable(UInt32),
    calling_station_id String,
    called_station_id String,
    src_number_in String,
    dst_number_in String,
    src_number_out String,
    dst_number_out String,
    in_trunkgroup_label String,
    out_trunkgroup_label String,
    accounting_status LowCardinality(String),
    q850_cause Nullable(UInt16),
    is_antifraud UInt8,
    completeness LowCardinality(String),
    defect LowCardinality(String),
    attributes Map(String, String),
    raw_event_ids Array(UUID)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(first_event_at)
ORDER BY (device_id, timezone_revision, transaction_id);

CREATE TABLE IF NOT EXISTS collector.correlation_dirty_buckets
(
    device_id UUID,
    timezone_revision UInt64,
    bucket Date,
    status LowCardinality(String),
    attempts UInt16,
    error String,
    updated_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (device_id, timezone_revision, bucket);

CREATE TABLE IF NOT EXISTS collector.call_assignments
(
    device_id UUID,
    timezone_revision UInt64,
    transaction_id UUID,
    updated_at DateTime64(6, 'UTC'),
    cdr_record_id Nullable(UUID),
    state LowCardinality(String),
    method LowCardinality(String),
    confidence Float32,
    time_delta_ms Int64,
    matched_fields Array(String),
    reason String,
    tombstone UInt8
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (device_id, timezone_revision, transaction_id);

CREATE TABLE IF NOT EXISTS collector.correlation_bucket_runs
(
    device_id UUID,
    timezone_revision UInt64,
    bucket Date,
    ran_at DateTime64(6, 'UTC'),
    total UInt64,
    exact UInt64,
    composite UInt64,
    ambiguous UInt64,
    orphan UInt64,
    duration_ms UInt64
)
ENGINE = ReplacingMergeTree(ran_at)
ORDER BY (device_id, timezone_revision, bucket);
