ALTER TABLE collector.device_derived_revisions
    ADD COLUMN IF NOT EXISTS cursor_received_us Int64 DEFAULT 0 AFTER cursor_event_id,
    ADD COLUMN IF NOT EXISTS cdr_cursor_ingested_us Int64 DEFAULT 0 AFTER cdr_cursor_record_id,
    ADD COLUMN IF NOT EXISTS high_watermark_us Int64 DEFAULT 0 AFTER high_watermark,
    ADD COLUMN IF NOT EXISTS cdr_high_watermark_us Int64 DEFAULT 0 AFTER cdr_high_watermark;
