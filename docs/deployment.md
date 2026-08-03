# Развёртывание и эксплуатация

Workload admission, split-role ownership, secret redaction, bounded
responses/searches, diagnostics, and the staging load SLO are defined in the
[security and performance operating contract](security-performance.md).

## Raw Syslog migration and retention

Before upgrading an existing installation, follow the fail-closed
[raw Syslog migration runbook](syslog-storage-migration.md). The JSON preflight
copies and verifies `raw_syslog` before startup is allowed to remove any legacy
Syslog-derived object.

Administrators manage retention through `GET /api/system/retention` and
`PATCH /api/system/retention`. The four independent policy classes are
`syslog`, `cdr` (equipment), `softswitch_cdr`, and `raw_cdr_archive`; each
accepts 7–1095 days and defaults to 1095.
`syslog` controls only `collector.syslog_messages`; the removed `derived`
policy is deleted during migration.
`softswitch_cdr` currently controls both Satel RTU ClickHouse tables and is the
contract for future typed softswitch parsers. Every valid change is effective
immediately, and the PATCH waits for the advisory-locked reconciliation
attempt before returning. A pending change can be cancelled with
`"cancel": true`.

The collector reconciles policies at startup and hourly under a PostgreSQL
advisory lock. ClickHouse TTL changes use a fixed table/column allowlist. The
raw CDR archive policy is shared by equipment and softswitches and installs a
MinIO lifecycle rule scoped only to `cdr/`;
the PostgreSQL `ingest_files` ledger, NATS streams, and durable spools are not
retention targets. A policy becomes active only after all resources for that
class have accepted the change; failures remain pending and expose
`lastError` for the hourly retry.

## Хост

Рекомендуемый старт для 10 SMG / 100 CPS peak:

- Linux x86_64, 16 vCPU, 64 GiB RAM;
- NVMe 2 TiB минимум, отдельный backup target;
- Docker Engine 27+ и Portainer;
- синхронизация NTP, UPS;
- management VLAN с маршрутами от SMG.

Фактический диск уточняется после 7-дневного canary: уровень Syslog влияет на объём на порядки.

## Portainer

1. Создайте external Docker-сеть `proxy`, если она ещё не создана, и подключите к ней существующий Nginx Proxy Manager.
2. Создайте Git Stack: repository `https://github.com/finenumbers/collector`, compose path `deploy/compose.yml`, reference `main`.
3. Добавьте environment variables из [.env.example](../.env.example) и четыре независимых секрета. Удалите старую переменную `COLLECTOR_VERSION`, если она осталась в Stack.
4. Deploy/redeploy stack. Сборка на Portainer не выполняется: `pull_policy: always` загружает готовый multi-arch образ `ghcr.io/finenumbers/collector:latest`.
5. Не публикуйте PostgreSQL, ClickHouse, NATS, MinIO, SFTPGo HTTP или app port `8080`.
6. Разрешите от SMG только `514/udp`, `21/tcp`, `50000-50100/tcp`.

`collector-ingress` работает в host network и единолично занимает `${SYSLOG_PORT:-514}/udp`. Это необходимо: bridge publish на данном классе Docker/Portainer SNAT-ит все SMG в адрес gateway и разрушает изоляцию по source IP. Основной `collector` остаётся в сетях `default` и `proxy`; NPM-конфигурация не меняется. Перед deploy убедитесь, что host rsyslog/syslog-ng не слушает этот UDP-порт.

## Nginx Proxy Manager

Collector подключён к external network `${PROXY_NETWORK:-proxy}` под уникальным alias `smg-collector`.

Настройка Proxy Host:

- Scheme: `http`;
- Forward Hostname: `smg-collector`;
- Forward Port: `8080`;
- SSL certificate: существующий сертификат NPM;
- Force SSL, HTTP/2 Support, Block Common Exploits: включить.

Публиковать `8080` на хосте не требуется. `SECURE_COOKIES=true`, поскольку внешний клиент работает через HTTPS NPM.

## Onboarding

После создания источника система атомарно создаёт:

- UUID, category и version-controlled template;
- SFTPGo principal, отдельный `/srv/cdr/<device_id>` и одноразовый FTP password;
- source-IP allowlist и parser profile только для шаблонов с Syslog/typed CDR;
- отображаемые параметры приёма согласно capabilities шаблона.

При ошибке SFTPGo database device компенсирующе удаляется.

Для Satel RTU выберите шаблон `satel-rtu-cdr-v1` (`Satel RTU`) и timezone, в которой
записаны timestamp файла. Загрузите CDR с 120-column header в корень того же FTP home:
исходник сначала фиксируется в MinIO, затем строки появляются во вкладке
«Вызовы и CDR». Collector выдаёт отдельный login с префиксом `ssw_`; Syslog IP и
AntiFraud для этого источника не настраиваются. MinIO/ledger failure оставляет
локальный файл для автоматического retry.

Satel CDR обогащается на ingest через FineNumbers PSTN и GeoIP (lookup workers
параллельно для PSTN∥GeoIP). В **Настройки → Параметры** задаются URL/токены,
`workers` (1–64, default 24) и фоновый **catch-up** (`enabled`, `pageSize`,
`sleep`) — maintenance-роль сама догоняет историю без ручного CLI.
`PSTN_LOOKUP_*` / `GEOIP_LOOKUP_*` в `.env` — только seed при пустой БД.

Прогресс: Dashboard KPI «Операторы»/«GeoIP»; в Диагностике — coverage 24h,
backlog, workers, lookups/cacheHits. Health `ok` ≠ полное покрытие истории.

Ручной one-shot (не прерывайте до `satel enrich complete`):

```bash
docker compose -f deploy/compose.yml run --rm collector satel-enrich
```

(`pstn-enrich-satel` — alias.)

## Backup and restore

### Daily backup

- `pg_dump -Fc collector` (Postgres control plane: users, devices, jobs, settings);
- ClickHouse backup or partition snapshot of database `collector`;
- MinIO bucket replication or filesystem snapshot of CDR archive volumes;
- SFTPGo data volume (`sftpgo_data`) plus compose/env secret material.

Store backups off the Docker host, encrypted. Single-host deployment is not HA.
Schedule a quarterly restore drill.

### Restore order (disaster recovery)

1. Stop collector/ingress/export/maintenance containers (leave volumes intact if partial).
2. Restore Postgres from `pg_dump` into a clean `collector` database; verify `users` and `devices` counts.
3. Restore ClickHouse `collector` database/partitions; verify `syslog_messages` and `cdr_records` (or Satel tables) row samples for the recovery window.
4. Restore MinIO / raw CDR volumes; spot-check one object key from `ingest_files`.
5. Restore SFTPGo volume if FTP home directories must match device credentials.
6. Restore or recreate empty durable spools (`ingress.db`, `syslog.db`) only if corrupted — prefer empty spools + live SMG catch-up over replaying stale spool bytes blindly.
7. Start stack; confirm `/health/ready`, admin login, one Syslog datagram from a canary SMG, one CDR file, AntiFraud list for that device.

Consistency note: Postgres job ledgers and ClickHouse snapshots can disagree after a partial restore; after DR, requeue failed projection jobs from Diagnostics and allow catch-up before trusting coverage SLOs.

### Secrets rotation (order)

Rotate one service at a time; keep a brief maintenance window:

1. Postgres (`POSTGRES_PASSWORD` / `DATABASE_URL`) — update env, recreate postgres + collector roles.
2. ClickHouse (`CLICKHOUSE_PASSWORD`) — update env; recreate clickhouse + collector; optional least-privilege API/export/maintenance users from compose stubs.
3. MinIO (`MINIO_ROOT_PASSWORD` / `MINIO_SECRET_KEY`) — update env; recreate minio + collector.
4. SFTPGo admin (`SFTPGO_ADMIN_PASSWORD`) — update env; recreate sftpgo + collector; device FTP user passwords are one-time UI secrets (re-provision if needed).
5. Confirm `ENVIRONMENT=production` and `SECURE_COOKIES=true`; production rejects default `collector:collector` Postgres URL and other seeded secrets.

## Retention

ClickHouse tables partitioned monthly и удаляют данные после 36 месяцев. Для 12-month hot / 3-year archive настройте отдельную storage policy после измерения дисков; текущая безопасная конфигурация не ссылается на несуществующий archive volume.

Raw CDR остаются в MinIO; lifecycle задаётся эксплуатационной политикой. Удаление устройства не должно автоматически стирать исторические данные.

## Мониторинг

Health endpoints:

- `/health/live` — process only;
- `/health/ready` — PostgreSQL и ClickHouse (compose healthcheck collector использует ready);
- `http://127.0.0.1:18081` на Docker-хосте — source-preserving ingress.

### ClickHouse / Postgres sizing notes

Baseline host (до ~10 SMG / 100 CPS): 16 vCPU / 64 GiB / NVMe ≥2 TiB — см. выше.
In-process query ceilings (`internal/analytics/workload.go`): Interactive 512 MiB /
2 threads (UI list/cards), CustomReplay 1 GiB / 1 thread (projection load/write),
CustomReconcile 1 GiB, Export 512 MiB. Runtime `projection.maxMemoryBytes` bounds
the Go hour payload **and** may raise CustomReplay/CustomReconcile ClickHouse
`max_memory_usage` above those floors (it does not lower them). Dense AF hours that
hit memory overflow are windowed in-process; keep headroom so Interactive card
lookups and CustomReplay do not contend on a saturated CH host. Prefer leaving
Postgres/ClickHouse without hard Docker memory caps below these ceilings unless
the host is dedicated and measured.

Операционные параметры AntiFraud / coverage / VoIPmonitor / export / ClickHouse
admission / **лимиты контейнеров** управляются в **Настройки → Параметры**
(`GET`/`PATCH /api/system/runtime-settings`). Они хранятся в PostgreSQL; `.env`
нужен для seed пустой БД и инфраструктурных секретов (БД, MinIO, SFTPGo, порты).
`platform.clickhouseAdmissionCapacity` применяется сразу для новых запросов;
уже выполняющиеся запросы сохраняют прежние лимиты до завершения.
Лимиты CPU/RAM: после сохранения скачайте
`/api/system/runtime-settings/container-limits.env`, перенесите значения в host
`.env` и выполните `docker compose up -d --force-recreate` (копия также пишется в
`/data/spool/container-limits.env`).

Административная панель «Диагностика» (lazy `GET /api/system/diagnostics`) показывает
очередь Custom projection (depth / **health lag** / failed / backfill), **per-device**
health vs event-tip ages, classification gap, coverage states и SLO, orphans/ambiguity,
очередь reconciliation и export queued/running/oldest.

### Diagnostics: signal vs noise

Читайте per-device метрики **в этом порядке**:

1. `failed` / `lastError` / `bucketDepth` — реальные hour jobs или отказ.
2. `healthLagSeconds` (**live** = `max(activated, contentLag)` при `bucketDepth>0`).
   `contentLag = max(0, AF tip − AF syslog tip)`. Абсолютный AF tip на тихом SMG
   (3 звонка) **не** красит SLO. Eternal discover не backlog.
3. `syslogLagSeconds` / `afSyslogLagSeconds` — жив ли ingest / AF-класс syslog.
4. `classificationGap` + `afAuthHeaders6h` / `xpgkHeaders6h` — диалект/логирование, не очередь.
5. CDR freshness (`Последний CDR` vs `Последний приём`) — отдельный сигнал FTP/CDR.

| Сигнал | Значение |
|--------|----------|
| `healthLagSeconds`, `contentLagSeconds` при `bucketDepth>0` | live projection health |
| `failed`, `lastError`, `bucketDepth` | health очереди |
| `oldestBucketAge` | catch-up (возраст старого hour job), **не** SLO |
| `afCallLagSeconds`, `eventTipLagSeconds`, `watermarkLagSeconds` | tip ages (на тихом SMG растут сами) |
| `afSyslogLagSeconds` | возраст последнего AF-classifiable syslog |
| `discoverAge`, eternal discover | не backlog work age |
| global `lagSeconds` (max activated) | может врать при stall одного SMG |

Операторский критерий SLO: `projectionSloMet` / live `maxDeviceLagSeconds`,
`anyDeviceFailed`, `anyClassificationGap`. Тихий Moscow с `activated≤300` и
`contentLag≈0` при catch-up 22ч — **SLO ok**; AF tip 1660с только informational.

Обязательные алерты: container restart, оба local spool depth/size (`ingress.db`,
`syslog.db`), handoff errors, NATS lag/storage, **per-device health lag** >5 мин при
`depth>0` или `failed>0`, classification gap, coverage late+missing >1% после grace,
CDR ingest age, disk >75/85%, ClickHouse insert errors, SFTPGo unavailable, backup age.

IANA timezone выбирается из выпадающего списка в настройках конкретного SMG и применяется
к CDR wall clock этого устройства. Сырой Syslog остаётся в `syslog_messages` с
`received_at`; Custom AntiFraud и coverage пересобираются фоновыми bucket jobs без
остановки приёма. Контролируйте projection lag, coverage SLO и ClickHouse read rows/CPU.

## Инциденты

- FTP недоступен: Eltex временно буферизует CDR в RAM (документировано до 30 MB); восстановите FTP до заполнения.
- NATS недоступен или достиг лимита 20 GiB: уже принятые datagrams остаются в `spool_data`; старые сообщения JetStream не вытесняются. Контролируйте оба диска и lag.
- Основной Collector недоступен: `collector-ingress` продолжает принимать UDP в `ingress.db`; после восстановления handoff автоматически воспроизводит очередь с исходными IP/port.
- Ingress не стартует с `address already in use`: освободите `${SYSLOG_PORT:-514}/udp` на Docker-хосте; не возвращайте bridge port mapping.
- ClickHouse недоступен: JetStream удерживает Syslog; CDR-файл остаётся в volume и raw archive/ledger.
- Upgrade с legacy Syslog storage: остановите app container, сделайте
  `pg_dump` + ClickHouse backup/snapshot immutable Syslog, затем выполните
  `migration-preflight` до cleanup; не продолжайте при `copyVerified=false`
  (см. [syslog-storage-migration.md](syslog-storage-migration.md)).

### Canary CDR ↔ Custom AntiFraud

1. Оставьте активным одно SMG с `antifraudEnabled=true` и дождитесь drain очереди projection.
2. В diagnostics проверьте `coverageSloMet` / `projectionSloMet` и отсутствие роста orphans/ambiguity.
3. Проверьте реальные пары по normalized `Acct-Session-Id`; разные session ID — разные вызовы.
4. Во время replay контролируйте oldest projection/reconciliation age и CPU: live budget
   не должен голодать.
5. Только после успешного canary включайте остальные SMG; рост lag или доли
   `late`/`missing`/`ambiguous` — причина остановки.

### Catch-up: AntiFraud projection stall на одном SMG

Симптом: syslog/CDR свежие, а на устройстве `depth>0` / `failed>0` / health lag >5 мин;
breach **прыгает** между SMG — смотрите health, не event tip. Global activated lag и
AF tip на тихом SMG (мало звонков) часто **шум**. Dense catch-up больше не должен
блокировать open UTC-hour: live hour lease-exempt при `projection.threads≥2`.

1. В «Диагностика» откройте `projectionDevices`: `failed`, `lastError`, `depth`,
   `healthLagSeconds`, `classificationGap`. Если `depth≈0`, `failed=0`, syslog свежий,
   а AF tip огромен — это не stall очереди (тихий tip), MaxEvents не поможет.
2. Если `lastError` содержит `exceeds … events` / `memory bound`:
   - временно снизьте нагрузку async export (делит ClickHouse heavy lane; admission
     предпочитает `custom_replay` над `export`);
   - в **Настройки → Параметры** поднимите `projection.maxEvents` (≥50000),
     `projection.maxMemoryBytes` (≥256MiB) и `projection.sleep=1s`
     (env `CUSTOM_PROJECTION_*` — только seed пустой БД);
   - `projection.threads≥2` рекомендуется для dense catch-up: open UTC-hour
     lease-exempt и может cutover’иться параллельно с одним closed-hour job.
3. Requeue failed jobs: admin
   `POST /api/devices/{deviceID}/projection/requeue-failed`
   (сбрасывает `failed`→`pending` для устройства и overflow-failed глобально).
   Либо SQL: `UPDATE custom_projection_jobs SET status='pending', attempts=0,
   next_attempt_at=now(), last_error=NULL WHERE device_id=$1 AND status='failed'`.
4. Worker при overflow сам режет час на окна 5m (и при необходимости 1m) и
   активирует snapshot один раз на финальном cutover — предыдущий tip остаётся
   видимым во время rebuild, чтобы карточки AF/CDR не ломались на partial
   snapshot. Пустой hour без AF events всё равно двигает watermark до конца bucket
   (или `now` для открытого часа), чтобы тихий SMG не замораживал tip forever.
   Перед CH write lease продлевается из `projection.lease`; CDR reconciliation /
   sibling hours / `NextDeadline` выполняются на cutover. Session expansion идёт
   через `event_id IN (session index)` (без hash JOIN syslog справа) и ограничена ±48h.
   Ошибки ClickHouse `memory limit exceeded` / `Query was cancelled`
   автоматически requeue’ятся и не блокируют catch-up навсегда. То же для
   временных сетевых ошибок ClickHouse (`connection refused`, `dial tcp`, …) —
   30s sweep возвращает их из `failed` без кнопки. После релиза нажмите
   «Requeue failed» в Диагностике только если `failed>0` с несвязанной ошибкой,
   и дождитесь drain.
5. Если jobs complete, syslog lag мал, но `afAuthHeaders6h=0` и
   `classificationGap=true` — это не очередь: на SMG нет classifiable AF RADIUS
   (логирование AntiFraud / диалект), поднимать MaxEvents бесполезно.
6. Дождитесь drain: per-device **health** lag ≤5 мин при `depth→0`; новые CDR снова
   получают coverage.
7. Toggle `antifraudEnabled` off→on — только после поднятых лимитов, если нужен
   новый discover/backfill.

### Staging canary: quiet + dense SMG

Перед promotion прогоните 30 минут с одним тихим и одним dense SMG:

- тихий mid-catch-up: `bucketDepth>0`, `activated≤300`, `contentLag≈0` → `projectionSloMet=ok`
  даже при AF tip ≫5 мин;
- dense: live health ≤5 мин; SLO не красит флот абсолютным tip тихого SMG;
- `oldestBucketAge` / `discoverAge` — catch-up only.
