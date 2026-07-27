CREATE TABLE IF NOT EXISTS collector.syslog_messages
(
    event_id UUID,
    device_id UUID,
    received_at DateTime64(6, 'UTC'),
    source_ip IPv6,
    source_port UInt16,
    transport LowCardinality(String),
    payload String,
    payload_sha256 FixedString(64)
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(received_at)
ORDER BY (device_id, received_at, event_id)
TTL toDateTime(received_at) + INTERVAL 36 MONTH DELETE;

INSERT INTO collector.syslog_messages
    (event_id, device_id, received_at, source_ip, source_port, transport, payload, payload_sha256)
SELECT
    source.event_id,
    source.device_id,
    source.received_at,
    source.source_ip,
    source.source_port,
    source.transport,
    source.payload,
    source.payload_sha256
FROM collector.raw_syslog AS source
LEFT ANTI JOIN collector.syslog_messages AS destination
    ON destination.device_id = source.device_id
   AND destination.received_at = source.received_at
   AND destination.event_id = source.event_id;
