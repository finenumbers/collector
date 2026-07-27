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

## Backup

Ежедневно:

- `pg_dump -Fc collector`;
- ClickHouse backup/partition snapshot;
- MinIO bucket replication либо filesystem snapshot;
- SFTPGo/PostgreSQL volumes metadata.

Backup хранится вне Docker-хоста, шифруется и проверяется restore-тестом ежеквартально. Single-host deployment не является HA.

## Retention

ClickHouse tables partitioned monthly и удаляют данные после 36 месяцев. Для 12-month hot / 3-year archive настройте отдельную storage policy после измерения дисков; текущая безопасная конфигурация не ссылается на несуществующий archive volume.

Raw CDR остаются в MinIO; lifecycle задаётся эксплуатационной политикой. Удаление устройства не должно автоматически стирать исторические данные.

## Мониторинг

Health endpoints:

- `/health/live` — process;
- `/health/ready` — PostgreSQL и ClickHouse.
- `http://127.0.0.1:18081` на Docker-хосте — source-preserving ingress.

Административная панель «Диагностика» (lazy `GET /api/system/diagnostics`) показывает
очередь Custom projection (depth/lag/failed/backfill), coverage states и SLO,
orphans/ambiguity, очередь reconciliation и export queued/running/oldest. Legacy
category breakdown и lifecycle counters удалены. Обязательные алерты: container restart,
оба local spool depth/size (`ingress.db`, `syslog.db`), handoff errors, NATS lag/storage,
projection lag >5 мин, coverage late+missing >1% после grace, CDR ingest age,
disk >75/85%, ClickHouse insert errors, SFTPGo unavailable, backup age.

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
- Upgrade с legacy Syslog storage: остановите app container и выполните
  `migration-preflight` до cleanup; не продолжайте при `copyVerified=false`.

### Canary CDR ↔ Custom AntiFraud

1. Оставьте активным одно SMG с `antifraudEnabled=true` и дождитесь drain очереди projection.
2. В diagnostics проверьте `coverageSloMet` / `projectionSloMet` и отсутствие роста orphans/ambiguity.
3. Проверьте реальные пары по normalized `Acct-Session-Id`; разные session ID — разные вызовы.
4. Во время replay контролируйте oldest projection/reconciliation age и CPU: live budget
   не должен голодать.
5. Только после успешного canary включайте остальные SMG; рост lag или доли
   `late`/`missing`/`ambiguous` — причина остановки.
