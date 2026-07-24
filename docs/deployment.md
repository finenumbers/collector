# Развёртывание и эксплуатация

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

После создания устройства система атомарно создаёт:

- UUID и source-IP allowlist;
- parser profile для firmware/timezone;
- SFTPGo principal и отдельный `/srv/cdr/<device_id>`;
- одноразовый FTP password;
- отображаемые параметры настройки SMG.

При ошибке SFTPGo database device компенсирующе удаляется.

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

В административной строке «Диагностика Syslog» отдельно показываются ingress
accepted/handoff/spool, app accepted/rejected, classified/raw coverage, active/building
timezone revision, Syslog/CDR replay counts, missing CDR time facts, lifecycle coverage
и инвариант `exact + composite + ambiguous + orphan = total`. Durable integer cursor
продолжает rebuild после рестарта. Обязательные алерты: container restart,
оба local spool depth/size (`ingress.db`, `syslog.db`), handoff errors, NATS lag/storage,
unknown source Syslog, unknown parser rate, persistent reprocess backlog, AntiFraud
orphan/incomplete rate, CDR ingest age, disk >75/85%, ClickHouse insert errors,
SFTPGo unavailable, backup age.

IANA timezone редактируется в настройках конкретного SMG. Сохранение создаёт новую
shadow revision и не удаляет текущие строки. UI продолжает использовать active timezone,
пока background rebuild пакетно пересобирает Syslog/CDR/lifecycle, проходит coverage и
catch-up. Только затем active revision переключается атомарно. Контролируйте replay
counts, ClickHouse read rows/CPU и correlation coverage
`exact/composite/ambiguous/orphan`.

## Инциденты

- FTP недоступен: Eltex временно буферизует CDR в RAM (документировано до 30 MB); восстановите FTP до заполнения.
- NATS недоступен или достиг лимита 20 GiB: уже принятые datagrams остаются в `spool_data`; старые сообщения JetStream не вытесняются. Контролируйте оба диска и lag.
- Основной Collector недоступен: `collector-ingress` продолжает принимать UDP в `ingress.db`; после восстановления handoff автоматически воспроизводит очередь с исходными IP/port.
- Ingress не стартует с `address already in use`: освободите `${SYSLOG_PORT:-514}/udp` на Docker-хосте; не возвращайте bridge port mapping.
- ClickHouse недоступен: JetStream удерживает Syslog; CDR-файл остаётся в volume и raw archive/ledger.
- Unknown растёт после firmware upgrade: не удаляйте raw, зафиксируйте firmware и добавьте golden fixtures/versioned parser.
