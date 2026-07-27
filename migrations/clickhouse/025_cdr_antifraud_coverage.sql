CREATE TABLE IF NOT EXISTS collector.cdr_antifraud_coverage
(
    device_id UUID,
    event_month Date,
    cdr_id UUID,
    policy_revision UInt64,
    reconciliation_version UInt32,
    projection_seq UInt64,
    state LowCardinality(String),
    expected_at DateTime64(6, 'UTC'),
    grace_expires_at DateTime64(6, 'UTC'),
    missing_terminal_at DateTime64(6, 'UTC'),
    retry_until DateTime64(6, 'UTC'),
    matched_call_id Nullable(UUID),
    method LowCardinality(String),
    reason LowCardinality(String),
    delta_ms Nullable(Int64),
    matched_evidence_json String,
    ambiguous UInt8,
    ambiguity_reason LowCardinality(String),
    updated_at DateTime64(6, 'UTC'),
    deleted UInt8 DEFAULT 0,
    INDEX coverage_cdr_bloom cdr_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(event_month)
ORDER BY (device_id, cdr_id, policy_revision, reconciliation_version);

CREATE TABLE IF NOT EXISTS collector.cdr_antifraud_assignments
(
    device_id UUID,
    event_month Date,
    assignment_id UUID,
    cdr_id UUID,
    call_id UUID,
    policy_revision UInt64,
    reconciliation_version UInt32,
    projection_seq UInt64,
    method LowCardinality(String),
    reason LowCardinality(String),
    delta_ms Nullable(Int64),
    matched_evidence_json String,
    assigned_at DateTime64(6, 'UTC'),
    ambiguous UInt8,
    ambiguity_reason LowCardinality(String),
    deleted UInt8 DEFAULT 0,
    INDEX assignment_cdr_bloom cdr_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX assignment_call_bloom call_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(projection_seq)
PARTITION BY toYYYYMM(event_month)
ORDER BY (device_id, cdr_id, call_id, assignment_id);

CREATE TABLE IF NOT EXISTS collector.cdr_reconciliation_dirty_buckets
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

CREATE VIEW IF NOT EXISTS collector.cdr_antifraud_coverage_current AS
SELECT *
FROM (SELECT * FROM collector.cdr_antifraud_coverage FINAL)
WHERE (device_id, cdr_id, projection_seq) IN
(
    SELECT device_id, cdr_id, max(projection_seq)
    FROM collector.cdr_antifraud_coverage
    GROUP BY device_id, cdr_id
)
AND deleted = 0;

CREATE VIEW IF NOT EXISTS collector.cdr_antifraud_assignments_current AS
SELECT *
FROM (SELECT * FROM collector.cdr_antifraud_assignments FINAL)
WHERE (device_id, cdr_id, call_id, projection_seq) IN
(
    SELECT device_id, cdr_id, call_id, max(projection_seq)
    FROM collector.cdr_antifraud_assignments
    GROUP BY device_id, cdr_id, call_id
)
AND deleted = 0;
