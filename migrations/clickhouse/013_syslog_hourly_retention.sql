DROP TABLE IF EXISTS collector.syslog_hourly_mv;
DROP TABLE IF EXISTS collector.syslog_hourly;

CREATE TABLE collector.syslog_hourly
(
    device_id UUID,
    hour DateTime64(6, 'UTC'),
    category LowCardinality(String),
    parse_status LowCardinality(String),
    events UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(hour)
ORDER BY (device_id, hour, category, parse_status)
TTL toDateTime(hour) + INTERVAL 1095 DAY DELETE;

CREATE MATERIALIZED VIEW collector.syslog_hourly_mv
TO collector.syslog_hourly
AS SELECT
    device_id,
    toStartOfHour(received_at) AS hour,
    category,
    parse_status,
    count() AS events
FROM collector.raw_syslog
GROUP BY device_id, hour, category, parse_status;

INSERT INTO collector.syslog_hourly
SELECT
    device_id,
    toStartOfHour(received_at) AS hour,
    category,
    parse_status,
    count() AS events
FROM collector.raw_syslog
GROUP BY device_id, hour, category, parse_status;
