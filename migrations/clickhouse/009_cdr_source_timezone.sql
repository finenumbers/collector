ALTER TABLE collector.device_derived_revisions
    ADD COLUMN IF NOT EXISTS cdr_source_timezone LowCardinality(String) DEFAULT 'UTC';

ALTER TABLE collector.device_derived_revisions
    ADD COLUMN IF NOT EXISTS cutover_sealed UInt8 DEFAULT 0;
