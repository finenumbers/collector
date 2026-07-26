ALTER TABLE collector.cdr_time_facts
    ADD COLUMN IF NOT EXISTS time_source LowCardinality(String) DEFAULT 'cdr_wall_clock';
