# Logs Collector

[![CI](https://github.com/finenumbers/collector/actions/workflows/ci.yml/badge.svg)](https://github.com/finenumbers/collector/actions/workflows/ci.yml)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Ffinenumbers%2Fcollector-blue)](https://github.com/finenumbers/collector/pkgs/container/collector)

Внутренний сервис приёма, нормализации и аналитики CDR/Syslog телеком-оборудования
и софтсвитчей. Поддерживаются Eltex SMG-1016M и typed CDR Satel RTU.

## Реализовано

- изолированная регистрация нескольких SMG по IP-источнику Syslog и отдельной FTP-учётной записи;
- host-network UDP ingress с сохранением реального source IP/port, отдельным durable handoff spool, JetStream без silent eviction, DLQ/quarantine и сохранением исходного payload;
- минимальный immutable `collector.syslog_messages`: исходные ID, UTC microseconds,
  source IP/port, transport, payload и SHA-256 без parser/category/derived полей;
- fail-closed upgrade через `migration-preflight` с count/checksum copy verification до удаления
  прежних Syslog/RADIUS/AntiFraud/construct/correlation объектов;
- приём CDR через SFTPGo FTP, неизменяемый raw-архив MinIO, UTF-8/Windows-1251 и динамический порядок колонок;
- отдельный header-driven Satel RTU parser, строгая автоактивация по immutable headers,
  versioned replay архивов из MinIO и специализированная CDR projection/UI без смешивания с Eltex;
- нормализация полного CDR, включая Acct-Session-Id, UniqueTag, SIP Call-ID, GCR, CIC и исходные поля;
- независимая IANA timezone-интерпретация CDR без Syslog-derived rebuild;
- Custom-only AntiFraud projection из `syslog_messages` с per-device toggle `antifraudEnabled`
  и coverage states `expected` / `late` / `matched` / `missing` / `ambiguous` / `not_applicable`;
- ClickHouse для событий/вызовов, PostgreSQL для пользователей, устройств, ingest и аудита;
- first-run создание администратора, Argon2id, серверные сессии, CSRF, lockout и RBAC;
- компактный светлый русскоязычный интерфейс: CDR, «Сообщения Syslog», Custom AntiFraud
  (вкладка скрыта при `antifraudEnabled=false`), coverage/dialogue drawers, sticky-заголовки,
  infinite scroll по 100 строк, поиск и потоковый CSV.zip;
- Docker Compose/Portainer stack для существующего Nginx Proxy Manager, health checks и закрытые внутренние сервисы.

## Установка через Portainer

1. Убедитесь, что external Docker-сеть NPM существует и называется `proxy`.
2. В Portainer создайте Stack из Git repository `https://github.com/finenumbers/collector`.
3. Compose path: `deploy/compose.yml`; reference: `main`.
4. Добавьте переменные из [.env.example](.env.example). Переменная версии образа не используется.
5. Deploy/redeploy stack. `pull_policy: always` всегда загрузит публичный multi-arch образ `ghcr.io/finenumbers/collector:latest`.
6. В NPM создайте Proxy Host: scheme `http`, hostname `smg-collector`, port `8080`; включите SSL, Force SSL, HTTP/2 и Block Common Exploits.

Порт `8080` не публикуется на Docker-хосте: NPM обращается к сервису только через сеть `proxy`. Отдельный `collector-ingress` использует host network только для `514/udp`, чтобы Docker SNAT не скрывал IP конкретного SMG. Откройте настроенный домен и создайте первого администратора. Затем добавьте SMG; система покажет одноразовые FTP-реквизиты и адрес Syslog.

Для локальной разработки можно собрать образ вручную и временно подключить тестовый reverse proxy. Production stack всегда использует GHCR.

## Образы и релизы

Release tag `vX.Y.Z` запускает GitHub Actions и публикует:

- `ghcr.io/finenumbers/collector:X.Y.Z`, `X.Y`, `X`, `latest` и `sha-*`;
- `linux/amd64` и `linux/arm64`;
- OCI labels, SBOM и signed GitHub build provenance attestation;
- GitHub Release с автоматически сформированными release notes.

Production Compose намеренно использует только `ghcr.io/finenumbers/collector:latest` с `pull_policy: always`.

## Настройка SMG

1. В `Трассировки → SYSLOG` укажите `PUBLIC_HOST`, UDP-порт `514`, включите нужные категории. Для длительного мониторинга Eltex рекомендует уровень `1`; `99` используйте только контролируемо.
2. В CDR включите строку имён полей и полный набор полей. Если заголовок отключён,
   сохраните ordered profile колонок в карточке SMG. `Device Sign` файла проверяется
   против карточки устройства. Укажите FTP `PUBLIC_HOST:21`, выданные логин/пароль и каталог `/`.
3. Настройте NTP и корректный timezone на шлюзе. Значение timezone также задаётся в карточке устройства.
4. Ограничьте доступ к портам `514/udp`, `21/tcp` и `50000-50100/tcp` management-сетью SMG. Host port `514/udp` должен быть свободен от rsyslog/syslog-ng.

## Проверка

```bash
npm --prefix web run build
docker run --rm -v "$PWD:/app" -w /app golang:1.25-alpine go test ./...
docker compose --env-file .env.example -f deploy/compose.yml config --quiet
```

Перед upgrade существующей установки выполните fail-closed
[`migration-preflight`](docs/syslog-storage-migration.md).

Подробности: [архитектура](docs/architecture.md), [модель данных](docs/data-dictionary.md), [корреляция](docs/correlation.md), [развёртывание](docs/deployment.md).

## Важное ограничение Syslog

Eltex не публикует исчерпывающую грамматику всех debug-сообщений 3.410. Collector всегда
сохраняет принятый raw payload в `syslog_messages` byte-for-byte. UI показывает эти
immutable сообщения как есть; semantic coverage Custom AntiFraud строится отдельной
фоновой проекцией и зависит от toggle `antifraudEnabled`. UDP не даёт подтверждения
доставки, поэтому абсолютную полноту до точки приёма гарантировать невозможно.
