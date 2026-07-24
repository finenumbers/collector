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
2. Создайте Git Stack: repository `https://github.com/finenumbers/collector`, compose path `deploy/compose.yml`, reference — release tag.
3. Добавьте environment variables из [.env.example](../.env.example), четыре независимых секрета и `COLLECTOR_VERSION=X.Y.Z`.
4. Deploy stack. Сборка на Portainer не выполняется: используется готовый multi-arch образ GHCR.
5. Не публикуйте PostgreSQL, ClickHouse, NATS, MinIO, SFTPGo HTTP или app port `8080`.
6. Разрешите от SMG только `514/udp`, `21/tcp`, `50000-50100/tcp`.

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

Обязательные алерты: container restart, local spool depth/size, NATS lag/storage, unknown source Syslog, unknown parser rate, CDR ingest age, disk >75/85%, ClickHouse insert errors, SFTPGo unavailable, backup age.

## Инциденты

- FTP недоступен: Eltex временно буферизует CDR в RAM (документировано до 30 MB); восстановите FTP до заполнения.
- NATS недоступен или достиг лимита 20 GiB: уже принятые datagrams остаются в `spool_data`; старые сообщения JetStream не вытесняются. Контролируйте оба диска и lag.
- ClickHouse недоступен: JetStream удерживает Syslog; CDR-файл остаётся в volume и raw archive/ledger.
- Unknown растёт после firmware upgrade: не удаляйте raw, зафиксируйте firmware и добавьте golden fixtures/versioned parser.
