ALTER TABLE collector.syslog_messages
    MODIFY TTL toDateTime(received_at) + INTERVAL 72 HOUR DELETE;
