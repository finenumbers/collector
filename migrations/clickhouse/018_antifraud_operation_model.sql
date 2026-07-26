CREATE TABLE IF NOT EXISTS collector.antifraud_calls
(
    device_id UUID,
    timezone_revision UInt64,
    parser_version LowCardinality(String),
    call_id UUID,
    updated_at DateTime64(6, 'UTC'),
    first_event_at DateTime64(6, 'UTC'),
    last_event_at DateTime64(6, 'UTC'),
    identity_kind LowCardinality(String),
    identity_value String,
    acct_session_id String,
    acct_session_id_normalized String,
    h323_conf_id String,
    call_contexts Array(String),
    raw_event_ids Array(UUID)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(first_event_at)
ORDER BY (device_id, timezone_revision, parser_version, call_id)
TTL toDateTime(first_event_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.antifraud_packets
(
    device_id UUID,
    timezone_revision UInt64,
    parser_version LowCardinality(String),
    packet_id UUID,
    updated_at DateTime64(6, 'UTC'),
    occurred_at DateTime64(6, 'UTC'),
    call_id UUID,
    operation_id Nullable(UUID),
    construct_anchor_event_id UUID,
    direction LowCardinality(String),
    packet_code LowCardinality(String),
    packet_identifier Nullable(UInt8),
    retry UInt16,
    completeness LowCardinality(String),
    terminal_reason LowCardinality(String),
    attribute_keys Array(String),
    attribute_values Array(String),
    attributes Map(String, String),
    raw_event_ids Array(UUID)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(occurred_at)
ORDER BY (device_id, timezone_revision, parser_version, packet_id)
TTL toDateTime(occurred_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.antifraud_operations
(
    device_id UUID,
    timezone_revision UInt64,
    parser_version LowCardinality(String),
    operation_id UUID,
    updated_at DateTime64(6, 'UTC'),
    first_event_at DateTime64(6, 'UTC'),
    last_event_at DateTime64(6, 'UTC'),
    call_id UUID,
    operation_type LowCardinality(String),
    occurrence UInt32,
    call_context String,
    acct_session_id_normalized String,
    request_packet_id Nullable(UUID),
    response_packet_id Nullable(UUID),
    terminal_state LowCardinality(String),
    terminal_reason LowCardinality(String),
    decision LowCardinality(String),
    q850_cause Nullable(UInt16),
    raw_event_ids Array(UUID)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(first_event_at)
ORDER BY (device_id, timezone_revision, parser_version, operation_id)
TTL toDateTime(first_event_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.antifraud_operation_cdr_links
(
    device_id UUID,
    timezone_revision UInt64,
    parser_version LowCardinality(String),
    operation_id UUID,
    updated_at DateTime64(6, 'UTC'),
    cdr_record_id Nullable(UUID),
    state LowCardinality(String),
    method LowCardinality(String),
    time_delta_ms Int64,
    reason LowCardinality(String)
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (device_id, timezone_revision, parser_version, operation_id);

CREATE OR REPLACE VIEW collector.current_antifraud_packets AS
SELECT
    device_id, timezone_revision, parser_version, packet_id,
    max(source.updated_at) AS updated_at,
    argMax(occurred_at, source.updated_at) AS occurred_at,
    argMax(call_id, source.updated_at) AS call_id,
    argMax(operation_id, source.updated_at) AS operation_id,
    argMax(construct_anchor_event_id, source.updated_at) AS construct_anchor_event_id,
    argMax(direction, source.updated_at) AS direction,
    argMax(packet_code, source.updated_at) AS packet_code,
    argMax(packet_identifier, source.updated_at) AS packet_identifier,
    argMax(retry, source.updated_at) AS retry,
    argMax(completeness, source.updated_at) AS completeness,
    argMax(terminal_reason, source.updated_at) AS terminal_reason,
    argMax(attribute_keys, source.updated_at) AS attribute_keys,
    argMax(attribute_values, source.updated_at) AS attribute_values,
    argMax(attributes, source.updated_at) AS attributes,
    argMax(raw_event_ids, source.updated_at) AS raw_event_ids
FROM collector.antifraud_packets AS source
GROUP BY device_id, timezone_revision, parser_version, packet_id;

CREATE OR REPLACE VIEW collector.current_antifraud_operations AS
SELECT
    device_id, timezone_revision, parser_version, operation_id,
    max(source.updated_at) AS updated_at,
    argMax(first_event_at, source.updated_at) AS first_event_at,
    argMax(last_event_at, source.updated_at) AS last_event_at,
    argMax(call_id, source.updated_at) AS call_id,
    argMax(operation_type, source.updated_at) AS operation_type,
    argMax(occurrence, source.updated_at) AS occurrence,
    argMax(call_context, source.updated_at) AS call_context,
    argMax(acct_session_id_normalized, source.updated_at) AS acct_session_id_normalized,
    argMax(request_packet_id, source.updated_at) AS request_packet_id,
    argMax(response_packet_id, source.updated_at) AS response_packet_id,
    argMax(terminal_state, source.updated_at) AS terminal_state,
    argMax(terminal_reason, source.updated_at) AS terminal_reason,
    argMax(decision, source.updated_at) AS decision,
    argMax(q850_cause, source.updated_at) AS q850_cause,
    argMax(raw_event_ids, source.updated_at) AS raw_event_ids
FROM collector.antifraud_operations AS source
GROUP BY device_id, timezone_revision, parser_version, operation_id;
