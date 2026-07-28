# Документация Collector

Внутренний сервис приёма Syslog/CDR, Custom AntiFraud и аналитики для Eltex SMG и Satel RTU.
Актуальная версия релизов: теги `vX.Y.Z` на GHCR (`latest` в Compose).

## С чего начать

| Кто вы | Куда идти |
|--------|-----------|
| Ставите стек первый раз | [Развёртывание и эксплуатация](deployment.md) → затем [Доступ и интерфейс](auth-and-ui.md) |
| Добавляете SMG / Satel | [deployment.md — Онбординг источников](deployment.md#онбординг-источников) |
| Разбираете AntiFraud / покрытие CDR | [CDR coverage и Custom AntiFraud](correlation.md) |
| Включаете VoIPmonitor | [VoIPmonitor](voipmonitor-correlation.md) |
| Экспорт CSV/XLSX | [Экспорт](exports.md) |
| Инцидент / stall проекции | [deployment.md — Инциденты и catch-up](deployment.md#инциденты) |
| Смотрите схему данных | [Словарь данных](data-dictionary.md) |
| Инженер пайплайна | [Архитектура](architecture.md), [Безопасность и производительность](security-performance.md) |
| Правила GitHub/релизов | [GitHub governance](github-governance.md) |

## Карта файлов

- [architecture.md](architecture.md) — пайплайны Syslog, CDR, AF, coverage, роли Compose
- [deployment.md](deployment.md) — хост, Portainer, секреты, health, источники, retention, backup, мониторинг
- [auth-and-ui.md](auth-and-ui.md) — bootstrap, RBAC, вкладки UI, Параметры, Диагностика
- [exports.md](exports.md) — sync/async экспорт
- [correlation.md](correlation.md) — канон Custom AntiFraud и coverage
- [voipmonitor-correlation.md](voipmonitor-correlation.md) — корреляция с VoIPmonitor
- [data-dictionary.md](data-dictionary.md) — PostgreSQL / ClickHouse / объекты
- [security-performance.md](security-performance.md) — admission, redaction, SLO
- [syslog-storage-migration.md](syslog-storage-migration.md) — one-shot миграция `raw_syslog` → `syslog_messages`
- [archive/syslog-audit.md](archive/syslog-audit.md) — исторический аудит (не runtime-контракт)

Корневой [README](../README.md) — краткий продукт и быстрый старт Portainer.
