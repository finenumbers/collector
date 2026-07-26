ALTER TABLE collector.call_assignments
    ADD COLUMN IF NOT EXISTS time_source LowCardinality(String) DEFAULT 'legacy';
