ALTER TABLE collector.device_derived_revisions
    ADD COLUMN IF NOT EXISTS reason LowCardinality(String) DEFAULT 'legacy';
