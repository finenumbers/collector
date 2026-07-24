ALTER TABLE collector.syslog_facts
    ADD INDEX IF NOT EXISTS category_idx category TYPE set(64) GRANULARITY 4;
