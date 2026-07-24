# SMG Collector

[![CI](https://github.com/finenumbers/collector/actions/workflows/ci.yml/badge.svg)](https://github.com/finenumbers/collector/actions/workflows/ci.yml)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Ffinenumbers%2Fcollector-blue)](https://github.com/finenumbers/collector/pkgs/container/collector)

Внутренний сервис приёма, нормализации и аналитики CDR/Syslog цифровых транковых шлюзов Eltex SMG-1016M. Целевая версия прошивки — `3.410.0.7443`.

## Реализовано

- изолированная регистрация нескольких SMG по IP-источнику Syslog и отдельной FTP-учётной записи;
- UDP Syslog receiver с retrying disk spool, JetStream без silent eviction, DLQ/quarantine и сохранением исходного payload;
- tolerant parser Eltex trace envelope, RFC3164/PRI и категорий alarm/call/SIP/ISUP/Q.931/IP/RADIUS/system journal;
- приём CDR через SFTPGo FTP, неизменяемый raw-архив MinIO, UTF-8/Windows-1251 и динамический порядок колонок;
- нормализация полного CDR, включая Acct-Session-Id, UniqueTag, SIP Call-ID, GCR, CIC и исходные поля;
- точная двусторонняя корреляция CDR↔RADIUS по `device_id + normalized Acct-Session-Id`;
- ClickHouse для событий/вызовов, PostgreSQL для пользователей, устройств, ingest и аудита;
- first-run создание администратора, Argon2id, серверные сессии, CSRF, lockout и RBAC;
- компактный русскоязычный интерфейс: логические разделы, «Все Syslog», cursor pagination всей истории, raw payload, поиск и потоковый многостраничный XLSX;
- Docker Compose/Portainer stack для существующего Nginx Proxy Manager, health checks и закрытые внутренние сервисы.

## Установка через Portainer

1. Убедитесь, что external Docker-сеть NPM существует и называется `proxy`.
2. В Portainer создайте Stack из Git repository `https://github.com/finenumbers/collector`.
3. Compose path: `deploy/compose.yml`; reference: release tag либо `main`.
4. Добавьте переменные из [.env.example](.env.example). Для воспроизводимого deploy задайте `COLLECTOR_VERSION` равным release tag без `v`, например `0.1.0`.
5. Deploy stack. Portainer загрузит публичный multi-arch образ `ghcr.io/finenumbers/collector`.
6. В NPM создайте Proxy Host: scheme `http`, hostname `smg-collector`, port `8080`; включите SSL, Force SSL, HTTP/2 и Block Common Exploits.

Порт `8080` не публикуется на Docker-хосте: NPM обращается к сервису только через сеть `proxy`. Откройте настроенный домен и создайте первого администратора. Затем добавьте SMG; система покажет одноразовые FTP-реквизиты и адрес Syslog.

Для локальной разработки можно собрать образ вручную и временно подключить тестовый reverse proxy. Production stack всегда использует GHCR.

## Образы и релизы

Release tag `vX.Y.Z` запускает GitHub Actions и публикует:

- `ghcr.io/finenumbers/collector:X.Y.Z`, `X.Y`, `X`, `latest` и `sha-*`;
- `linux/amd64` и `linux/arm64`;
- OCI labels, SBOM и signed GitHub build provenance attestation;
- GitHub Release с автоматически сформированными release notes.

## Настройка SMG

1. В `Трассировки → SYSLOG` укажите `PUBLIC_HOST`, UDP-порт `514`, включите нужные категории. Для длительного мониторинга Eltex рекомендует уровень `1`; `99` используйте только контролируемо.
2. В CDR включите строку имён полей и полный набор полей. Укажите FTP `PUBLIC_HOST:21`, выданные логин/пароль и каталог `/`.
3. Настройте NTP и корректный timezone на шлюзе. Значение timezone также задаётся в карточке устройства.
4. Ограничьте доступ к портам `514/udp`, `21/tcp` и `50000-50100/tcp` management-сетью SMG.

## Проверка

```bash
npm --prefix web run build
docker run --rm -v "$PWD:/app" -w /app golang:1.25-alpine go test ./...
docker compose --env-file .env.example -f deploy/compose.yml config --quiet
```

Подробности: [архитектура](docs/architecture.md), [модель данных](docs/data-dictionary.md), [корреляция](docs/correlation.md), [развёртывание](docs/deployment.md).

## Важное ограничение Syslog

Eltex не публикует исчерпывающую грамматику всех debug-сообщений 3.410. Collector всегда сохраняет принятый raw payload; все записи доступны в «Все Syslog», а неизвестные дополнительно видны в «Нераспознанное». Семантическое покрытие расширяется версионированными parser fixtures после накопления реального corpus. UDP не даёт подтверждения доставки, поэтому абсолютную полноту до точки приёма гарантировать невозможно.
