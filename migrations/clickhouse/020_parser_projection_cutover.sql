CREATE TABLE IF NOT EXISTS collector.parser_projection_state
(
    device_id UUID,
    timezone_revision UInt64,
    parser_version LowCardinality(String),
    status LowCardinality(String),
    updated_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (device_id, timezone_revision, parser_version);
