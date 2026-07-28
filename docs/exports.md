# Экспорт

Sync и async выгрузка датасетов Collector в файлы.
Доступ и роли — [auth-and-ui.md](auth-and-ui.md); нагрузка на ClickHouse пересекается
с projection — см. [security-performance.md](security-performance.md).

---

## Датасеты

| `dataset` | Источник | Sync | Async |
|-----------|----------|------|-------|
| `calls` | CDR (Eltex / контекст устройства) | да (XLSX) | да |
| `syslog` | `syslog_messages` | только **с поиском** | да (полный syslog — только async) |
| `antifraud` | Custom AntiFraud calls | **нет** | да, формат **только** `csv_zip` |

---

## Sync (`/export` XLSX)

- Доступно для `calls` и **searched** `syslog`.
- Полный syslog без search → **413**: создайте async job (`/export-jobs`).
- `antifraud` sync запрещён → async `csv_zip`.
- Жёсткий потолок строк sync: **50 000**.
- Лимит листа XLSX: **1 048 576** строк.

Проверка: заголовок ответа `X-Export-Dataset`, имя файла в `Content-Disposition` /
`X-Export-*` metadata.

---

## Async (`/export-jobs`)

### Форматы

| `format` | Когда |
|----------|--------|
| `xlsx` | Ограниченные выборки |
| `csv_zip` | Крупные выгрузки; **обязателен** для `antifraud` |
| `auto` | → `csv_zip`, если нет диапазона дат **или** оценка syslog > **250 000** строк |

### Очередь и владение

- Не более **3** active/queued jobs на пользователя.
- Не более **5** на устройство.
- Stale queued: **10 минут**; heartbeat running: **2 минуты**.
- Cancel: владелец job или admin. `queued` → `cancelled`; `running` →
  `cancel_requested_at` (worker останавливается на checkpoint).

### Фильтры

- Search ≤ **256** символов.
- Нужны `from`/`to`, если не admin `allTime`.
- Диапазон ≤ **31** день.

### Артефакты

- После complete/fail/cancel: `expires_at` = **7 дней**.
- Объекты в MinIO под `exports/` с lifecycle **7 дней**.
- Скачивание по API job, пока не `expired`.

---

## Contention с projection

Async export и CustomReplay делят ClickHouse admission / heavy lane.
При catch-up AF на плотном SMG:

1. временно не запускайте крупные export jobs;
2. следите за `export` counters в Диагностике;
3. при OOM / lag projection — см. [deployment.md §14](deployment.md#14-canary-и-catch-up).

`platform.exportPageSize` (default `1000`) и `clickhouseAdmissionCapacity`
настраиваются в Параметрах.

---

## Типичные ошибки

| Симптом | Действие |
|---------|----------|
| 413 на sync syslog | Добавьте search или создайте async job |
| antifraud + xlsx | Используйте `csv_zip` |
| 429 / queue full | Дождитесь завершения или cancel старых jobs |
| Пустой/expired download | Артефакт старше 7 дней — пересоздайте job |
| Export тормозит AF | Снизьте параллелизм export, поднимите projection limits после canary |
