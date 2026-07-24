ALTER TABLE collector.raw_syslog
    ADD COLUMN IF NOT EXISTS source_timezone LowCardinality(String) DEFAULT 'UTC' AFTER attributes,
    ADD COLUMN IF NOT EXISTS source_utc_offset_minutes Int16 DEFAULT 0 AFTER source_timezone;

ALTER TABLE collector.radius_events
    ADD COLUMN IF NOT EXISTS packet_transaction_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000') AFTER transaction_id,
    ADD COLUMN IF NOT EXISTS parser_version LowCardinality(String) DEFAULT 'smg-3.410-v5' AFTER completeness;

ALTER TABLE collector.cdr_records
    ADD COLUMN IF NOT EXISTS source_timezone LowCardinality(String) DEFAULT 'UTC' AFTER raw_fields,
    ADD COLUMN IF NOT EXISTS source_utc_offset_minutes Int16 DEFAULT 0 AFTER source_timezone;

ALTER TABLE collector.syslog_reprocess_ledger
    ADD COLUMN IF NOT EXISTS device_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000') AFTER event_id;

CREATE TABLE IF NOT EXISTS collector.syslog_interpretations
(
    event_id UUID,
    device_id UUID,
    interpreted_at DateTime64(6, 'UTC'),
    parser_version LowCardinality(String),
    parse_status LowCardinality(String),
    category LowCardinality(String),
    event_time Nullable(DateTime64(6, 'UTC')),
    component LowCardinality(String),
    message String,
    attributes Map(String, String),
    source_timezone LowCardinality(String),
    source_utc_offset_minutes Int16
)
ENGINE = ReplacingMergeTree(interpreted_at)
ORDER BY (device_id, event_id);

CREATE TABLE IF NOT EXISTS collector.cdr_time_interpretations
(
    record_id UUID,
    device_id UUID,
    interpreted_at DateTime64(6, 'UTC'),
    setup_time Nullable(DateTime64(6, 'UTC')),
    connect_time Nullable(DateTime64(6, 'UTC')),
    disconnect_time Nullable(DateTime64(6, 'UTC')),
    source_timezone LowCardinality(String),
    source_utc_offset_minutes Int16
)
ENGINE = ReplacingMergeTree(interpreted_at)
ORDER BY (device_id, record_id);

CREATE TABLE IF NOT EXISTS collector.antifraud_call_links
(
    device_id UUID,
    transaction_id UUID,
    cdr_record_id UUID,
    linked_at DateTime64(3, 'UTC'),
    method LowCardinality(String),
    confidence Float32,
    ambiguity UInt8,
    candidate_reason String,
    time_delta_ms Int64,
    evidence Map(String, String),
    parser_version LowCardinality(String)
)
ENGINE = ReplacingMergeTree(linked_at)
ORDER BY (device_id, transaction_id, cdr_record_id, method);

CREATE TABLE IF NOT EXISTS collector.correlation_runs
(
    device_id UUID,
    ran_at DateTime64(3, 'UTC'),
    parser_version LowCardinality(String),
    antifraud_total UInt64,
    exact_linked UInt64,
    composite_linked UInt64,
    ambiguous UInt64,
    orphan UInt64
)
ENGINE = ReplacingMergeTree(ran_at)
ORDER BY (device_id, parser_version);
