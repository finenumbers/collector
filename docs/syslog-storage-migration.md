# Raw Syslog storage migration

The upgrade replaces `collector.raw_syslog` and every legacy Syslog
classification/RADIUS/AntiFraud/correlation projection with the immutable
`collector.syslog_messages` table. CDR and Satel RTU tables are not part of
this cleanup.

## Preflight

Stop the application container so no worker can race the copy. Keep
PostgreSQL and ClickHouse running, then execute:

```bash
docker compose -f deploy/compose.yml stop collector
docker compose -f deploy/compose.yml run --rm collector migration-preflight
```

The command applies ClickHouse migrations only through the create/copy phase
and prints one JSON object. It exits non-zero unless:

- the source and destination row counts match;
- deterministic aggregate `sum` and `xor` digests over all eight immutable
  columns match;
- PostgreSQL has no `pending` or `running` legacy parser rebuild job;
- both source and destination tables are queryable.

`legacyTables` is the inventory that cleanup will remove.
`availableDiskBytes` is reported when ClickHouse exposes `system.disks`; it is
informational because storage policies may use remote or shared capacity.

Do not continue if `copyVerified` or `readyForCleanup` is false. The source
table is retained on every verification failure.

## Upgrade

After a successful preflight, start the application normally:

```bash
docker compose -f deploy/compose.yml up -d collector
```

Startup checks the legacy PostgreSQL queue again, applies PostgreSQL migration
`017`, runs ClickHouse create/copy idempotently, repeats the copy verification,
and only then applies ClickHouse cleanup migration `023`. This all completes
before NATS, Syslog, CDR, export, or HTTP workers start.

The NATS durable consumer is intentionally still named `syslog-parser` during
this transition. The name is an upgrade compatibility seam only; its runtime
behavior is raw insertion into `syslog_messages`.

## Schema contract

`syslog_messages` contains only `event_id`, `device_id`, `received_at`,
`source_ip`, `source_port`, `transport`, `payload`, and `payload_sha256`.
Copying uses those source columns directly; IDs, UTC microsecond timestamps,
payload bytes, and stored SHA-256 text are not regenerated.
