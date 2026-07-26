ALTER TABLE collector.raw_syslog MODIFY TTL toDateTime(received_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.syslog_interpretations MODIFY TTL toDateTime(interpreted_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.syslog_facts MODIFY TTL toDateTime(received_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.syslog_fragment_links MODIFY TTL toDateTime(linked_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.syslog_constructs MODIFY TTL toDateTime(started_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.syslog_construct_members MODIFY TTL toDateTime(linked_at) + INTERVAL 1095 DAY DELETE;

ALTER TABLE collector.cdr_records MODIFY TTL toDateTime(coalesce(setup_time, ingested_at)) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.cdr_time_interpretations MODIFY TTL toDateTime(interpreted_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.cdr_time_facts MODIFY TTL toDateTime(interpreted_at) + INTERVAL 1095 DAY DELETE;

ALTER TABLE collector.radius_events MODIFY TTL toDateTime(occurred_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.antifraud_transactions MODIFY TTL toDateTime(first_event_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.call_event_links MODIFY TTL toDateTime(linked_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.call_correlation_candidates MODIFY TTL toDateTime(created_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.antifraud_call_links MODIFY TTL toDateTime(linked_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.correlation_runs MODIFY TTL toDateTime(ran_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.radius_fragments MODIFY TTL toDateTime(occurred_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.antifraud_lifecycles MODIFY TTL toDateTime(first_event_at) + INTERVAL 1095 DAY DELETE;
ALTER TABLE collector.call_assignments MODIFY TTL toDateTime(updated_at) + INTERVAL 1095 DAY DELETE;

-- Operational state is intentionally shorter than user data. Active/building revisions and
-- unfinished dirty buckets are retained regardless of age, preserving replay idempotency.
ALTER TABLE collector.correlation_bucket_runs
  MODIFY TTL toDateTime(ran_at) + INTERVAL 90 DAY DELETE;
ALTER TABLE collector.correlation_dirty_buckets
  MODIFY TTL toDateTime(updated_at) + INTERVAL 30 DAY DELETE WHERE status = 'done';
ALTER TABLE collector.device_derived_revisions
  MODIFY TTL toDateTime(updated_at) + INTERVAL 90 DAY DELETE
  WHERE status NOT IN ('active', 'building', 'cutover', 'ready');
