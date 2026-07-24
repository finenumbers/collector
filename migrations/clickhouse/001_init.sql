CREATE DATABASE IF NOT EXISTS collector;

CREATE TABLE IF NOT EXISTS collector.raw_syslog
(
    event_id UUID,
    device_id UUID,
    received_at DateTime64(6, 'UTC'),
    source_ip IPv6,
    source_port UInt16,
    transport LowCardinality(String),
    payload String,
    payload_sha256 FixedString(64),
    pri Nullable(UInt16),
    facility Nullable(UInt8),
    severity Nullable(UInt8),
    header_format LowCardinality(String),
    parser_version LowCardinality(String),
    parse_status LowCardinality(String),
    category LowCardinality(String),
    event_time Nullable(DateTime64(6, 'UTC')),
    component LowCardinality(String),
    message String,
    attributes Map(String, String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (device_id, received_at, event_id)
TTL toDateTime(received_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.cdr_records
(
    record_id UUID,
    device_id UUID,
    file_id UUID,
    row_number UInt64,
    ingested_at DateTime64(3, 'UTC'),
    sequence_number String,
    boot_epoch String,
    sequence UInt64,
    setup_time Nullable(DateTime64(3, 'UTC')),
    connect_time Nullable(DateTime64(3, 'UTC')),
    disconnect_time Nullable(DateTime64(3, 'UTC')),
    duration_ms Nullable(UInt64),
    release_cause Nullable(UInt16),
    release_info LowCardinality(String),
    release_side LowCardinality(String),
    incoming_ip Nullable(IPv6),
    outgoing_ip Nullable(IPv6),
    incoming_type LowCardinality(String),
    outgoing_type LowCardinality(String),
    incoming_description String,
    outgoing_description String,
    incoming_cgpn String,
    outgoing_cgpn String,
    incoming_cdpn String,
    outgoing_cdpn String,
    incoming_sip_call_id String,
    outgoing_sip_call_id String,
    incoming_ss7_cic Nullable(UInt32),
    outgoing_ss7_cic Nullable(UInt32),
    radius_session_id String,
    radius_session_id_normalized String,
    global_callref String,
    unique_tag String,
    transfer_mark LowCardinality(String),
    rejecting_radius_server String,
    raw_fields Map(String, String)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(coalesce(setup_time, ingested_at))
ORDER BY (device_id, sequence_number, record_id)
TTL toDateTime(coalesce(setup_time, ingested_at)) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.radius_events
(
    event_id UUID,
    device_id UUID,
    occurred_at DateTime64(6, 'UTC'),
    direction LowCardinality(String),
    packet_code LowCardinality(String),
    packet_identifier Nullable(UInt8),
    request_type LowCardinality(String),
    server_address String,
    acct_session_id String,
    acct_session_id_normalized String,
    calling_station_id String,
    called_station_id String,
    result LowCardinality(String),
    retry UInt16,
    latency_ms Nullable(UInt32),
    attributes Map(String, String),
    raw_event_id UUID
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (device_id, acct_session_id_normalized, occurred_at, event_id)
TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.call_event_links
(
    device_id UUID,
    cdr_record_id UUID,
    event_id UUID,
    method LowCardinality(String),
    confidence Float32,
    evidence Map(String, String),
    parser_version LowCardinality(String),
    linked_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(linked_at)
ORDER BY (device_id, cdr_record_id, event_id, method);

CREATE MATERIALIZED VIEW IF NOT EXISTS collector.syslog_hourly
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (device_id, hour, category, parse_status)
AS SELECT
    device_id,
    toStartOfHour(received_at) AS hour,
    category,
    parse_status,
    count() AS events
FROM collector.raw_syslog
GROUP BY device_id, hour, category, parse_status;
