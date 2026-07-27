# Raw Syslog storage migration

The upgrade replaces `collector.raw_syslog` and every legacy Syslog
classification/RADIUS/AntiFraud/correlation projection with the immutable
`collector.syslog_messages` table. CDR and Satel RTU tables are not part of
this cleanup.

## Preflight

Stop the application container so no worker can race the copy. Keep
PostgreSQL and ClickHouse running. Take an off-host backup before any
destructive cleanup — copy verification protects against a bad copy, but it
is not a restore point:

```bash
docker compose -f deploy/compose.yml stop collector
docker compose -f deploy/compose.yml exec -T postgres \
  pg_dump -Fc -U collector collector > "collector-pg-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose -f deploy/compose.yml exec -T clickhouse \
  clickhouse-client --user collector --password "$CLICKHOUSE_PASSWORD" \
  --query "BACKUP TABLE collector.raw_syslog TO Disk('default', 'backups/raw_syslog-$(date -u +%Y%m%dT%H%M%SZ)')"
```

If your ClickHouse build or storage policy does not support `BACKUP TABLE`,
take a filesystem/volume snapshot of the ClickHouse data directory instead
(see [Backup](deployment.md#backup)). Keep the dump and snapshot until the
new release has served production traffic and retention/purge look healthy.

Then verify the immutable copy:

```bash
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
