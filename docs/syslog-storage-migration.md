# Миграция хранилища raw Syslog

> One-shot runbook для инсталляций, ещё держащих legacy `collector.raw_syslog`.
> Новые стеки на актуальном образе этот путь не проходят.
> Вызов из операторского гайда: [deployment.md — Upgrade](deployment.md#13-upgrade)
> и раздел инцидентов про legacy storage.

Upgrade заменяет `collector.raw_syslog` и все legacy Syslog
classification/RADIUS/AntiFraud/correlation projection на immutable
`collector.syslog_messages`. Таблицы CDR и Satel RTU в cleanup **не** входят.

## Preflight

Остановите application-контейнер, чтобы worker не гонялся с copy. PostgreSQL и
ClickHouse оставьте running. Сделайте off-host backup **до** destructive cleanup —
проверка copy защищает от плохой копии, но не заменяет restore point
(см. [Backup / restore](deployment.md#10-backup--restore--ротация-секретов)):

```bash
docker compose -f deploy/compose.yml stop collector
docker compose -f deploy/compose.yml exec -T postgres \
  pg_dump -Fc -U collector collector > "collector-pg-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose -f deploy/compose.yml exec -T clickhouse \
  clickhouse-client --user collector --password "$CLICKHOUSE_PASSWORD" \
  --query "BACKUP TABLE collector.raw_syslog TO Disk('default', 'backups/raw_syslog-$(date -u +%Y%m%dT%H%M%SZ)')"
```

Если `BACKUP TABLE` недоступен — filesystem/volume snapshot каталога данных
ClickHouse. Держите dump/snapshot, пока новый релиз не отработает в production
и retention/purge не выглядят здоровыми.

Затем проверьте immutable copy:

```bash
docker compose -f deploy/compose.yml run --rm collector migration-preflight
```

Команда применяет ClickHouse-миграции только до фазы create/copy и печатает
один JSON. Exit non-zero, пока не выполнено:

- совпали counts source/destination;
- совпали deterministic aggregate `sum` и `xor` digests по всем восьми
  immutable-колонкам (включая payload bytes и stored hash);
- в PostgreSQL нет `pending`/`running` legacy parser rebuild job;
- обе таблицы queryable.

`legacyTables` — inventory, который cleanup удалит.
`availableDiskBytes` информативен (политики могут использовать remote capacity).

**Не продолжайте**, если `copyVerified` или `readyForCleanup` = false.
Source table при любом провале verification сохраняется.

## Upgrade

После успешного preflight поднимите application:

```bash
docker compose -f deploy/compose.yml up -d collector
```

Startup снова проверяет legacy PG queue, применяет PostgreSQL migration `017`,
идемпотентно гоняет ClickHouse create/copy, повторяет verification и только
затем cleanup migration `023`. Всё завершается **до** старта NATS/Syslog/CDR/
export/HTTP workers.

Durable consumer NATS по-прежнему может называться `syslog-parser` — это только
compatibility seam имени; runtime-поведение = raw insert в `syslog_messages`.

## Schema contract

`syslog_messages` содержит только `event_id`, `device_id`, `received_at`,
`source_ip`, `source_port`, `transport`, `payload`, `payload_sha256`.
Copy использует эти колонки напрямую; ID, UTC µs timestamps, payload bytes и
stored SHA-256 text **не** перегенерируются.
