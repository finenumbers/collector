# Logs Collector

[![CI](https://github.com/finenumbers/collector/actions/workflows/ci.yml/badge.svg)](https://github.com/finenumbers/collector/actions/workflows/ci.yml)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Ffinenumbers%2Fcollector-blue)](https://github.com/finenumbers/collector/pkgs/container/collector)

Внутренний сервис приёма, хранения и аналитики **Syslog** и **CDR** телеком-оборудования
и софтсвитчей. Поддерживаются **Eltex SMG-1016M** (профили 3.23.2 / 3.410) и typed CDR
**Satel RTU**.

## Возможности

- несколько SMG с изоляцией по IP Syslog и отдельной FTP-учётной записью;
- host-network UDP ingress с сохранением реального source IP/port, durable spool и JetStream;
- immutable `collector.syslog_messages` (без parser/category в сырье);
- Custom AntiFraud из Syslog с `antifraudEnabled`, coverage CDR↔AF и карточками вызова;
- CDR Eltex и Satel через SFTPGo → MinIO raw-архив → ClickHouse;
- опциональная корреляция с VoIPmonitor;
- async-экспорт, retention, диагностика, runtime-параметры в UI;
- Docker Compose / Portainer рядом с Nginx Proxy Manager.

## Быстрый старт (Portainer)

1. External Docker-сеть NPM с именем `proxy` (или задайте `PROXY_NETWORK`).
2. Stack из Git `https://github.com/finenumbers/collector`, compose path `deploy/compose.yml`, reference `main`.
3. Переменные из [.env.example](.env.example) (четыре независимых секрета ≥32 символов, `PUBLIC_HOST`, `SECURE_COOKIES=true`).
4. Deploy. Образ: `ghcr.io/finenumbers/collector:latest` с `pull_policy: always` (переменная версии образа не нужна).
5. В NPM: Proxy Host → `http` / hostname `smg-collector` / port `8080`; SSL, Force SSL, HTTP/2, Block Common Exploits.
6. Откройте UI, создайте первого администратора, добавьте устройство.

Порт `8080` приложения на хост **не** публикуется — только сеть `proxy`. Syslog слушает
host-network `${SYSLOG_PORT:-514}/udp`. FTP: `${FTP_PORT:-21}` и passive `50000–50100`.

## Документация

Полная карта: **[docs/README.md](docs/README.md)**.

| Документ | Содержание |
|----------|------------|
| [Развёртывание](docs/deployment.md) | Хост, секреты, источники, backup, мониторинг, инциденты |
| [Доступ и UI](docs/auth-and-ui.md) | Роли, bootstrap, Параметры, Диагностика |
| [AntiFraud / coverage](docs/correlation.md) | Модель вызова и покрытие CDR |
| [Экспорт](docs/exports.md) | CSV/XLSX, sync и async |
| [Архитектура](docs/architecture.md) | Пайплайны и роли Compose |

## Проверка после установки

```bash
curl -fsS "http://127.0.0.1:18081/"          # ingress
curl -fsS "https://<ваш-домен>/api/bootstrap/status"
```

Дальше: одно SMG с Device Sign, Syslog с шлюза, один CDR-файл, при необходимости
включить AntiFraud и дождаться drain очереди проекции (см. [deployment.md](docs/deployment.md)).
