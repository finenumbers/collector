CREATE TABLE IF NOT EXISTS collector.syslog_fragment_links
(
    device_id UUID,
    timezone_revision UInt64,
    grouping_version LowCardinality(String),
    child_event_id UUID,
    parent_event_id UUID,
    link_method LowCardinality(String),
    fragment_kind LowCardinality(String),
    confidence Float32,
    linked_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(linked_at)
ORDER BY (device_id, timezone_revision, grouping_version, child_event_id)
TTL toDateTime(linked_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.syslog_constructs
(
    device_id UUID,
    timezone_revision UInt64,
    grouping_version LowCardinality(String),
    construct_id UUID,
    updated_at DateTime64(6, 'UTC'),
    started_at DateTime64(6, 'UTC'),
    ended_at DateTime64(6, 'UTC'),
    construct_type LowCardinality(String),
    category LowCardinality(String),
    direction LowCardinality(String),
    title String,
    summary String,
    call_context String,
    message_name String,
    completeness LowCardinality(String),
    grouping_method LowCardinality(String),
    grouping_reason String,
    confidence Float32,
    member_count UInt32,
    hidden_count UInt32,
    searchable_text String,
    attributes Map(String, String)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(started_at)
ORDER BY (device_id, timezone_revision, grouping_version, construct_id)
TTL toDateTime(started_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.syslog_construct_members
(
    device_id UUID,
    timezone_revision UInt64,
    grouping_version LowCardinality(String),
    construct_id UUID,
    event_id UUID,
    ordinal UInt32,
    role LowCardinality(String),
    technical UInt8,
    linked_at DateTime64(6, 'UTC')
)
ENGINE = ReplacingMergeTree(linked_at)
ORDER BY (device_id, timezone_revision, grouping_version, construct_id, event_id)
TTL toDateTime(linked_at) + INTERVAL 36 MONTH DELETE;
