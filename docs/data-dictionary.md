# Словарь данных

Control-plane (PostgreSQL), аналитика (ClickHouse) и object keys (MinIO).
Модель AF — [correlation.md](correlation.md); архитектура — [architecture.md](architecture.md).

Актуальные миграции: PostgreSQL до **023**, ClickHouse до **030**.

---

## PostgreSQL (control plane)

### `users` / `sessions`

Роли: `admin` | `analyst` | `viewer`. Lockout: `failed_attempts`, `locked_until`.
Сессии: `id_hash`, `csrf_hash`, `expires_at` (TTL 12h на стороне приложения).

### `devices`

Ключевые поля: шаблон (`template_key` / firmware profile), `syslog_source_ip`,
`device_sign`, `timezone`, FTP home/username, `antifraud_enabled`,
`antifraud_policy_revision`, `voipmonitor_enabled`, category/capabilities шаблона.

`antifraud_enabled` — единственный runtime-switch AF. Каждый toggle меняет
`antifraud_policy_revision`. Legacy `antifraud_mode` / parser rebuild queue
удалены миграциями foundation.

### `ingest_files`

Immutable ledger raw CDR: `object_key`, `sha256`, `status`
(`received`/`processing`/`processed`/`quarantined`/`failed`), counts, errors.
Не цель retention policy classes.

### `export_jobs`

Durable async export queue. Важные колонки:

| Поле | Смысл |
|------|--------|
| `dataset` | `calls` / `syslog` / `antifraud` |
| `format` | `auto` / `xlsx` / `csv_zip` |
| `status` | `queued`/`running`/`completed`/`failed`/`cancelled`/`expired` |
| `search`, `range_from`/`range_to` | Фильтры |
| `object_key`, `sha256`, `size_bytes` | Артефакт в MinIO |
| `rows_estimated` / `rows_processed` | Прогресс |
| `cancel_requested_at` | Мягкая отмена running |
| `heartbeat_at` / `lease_expires_at` / `worker_id` | Владение worker’ом |
| `expires_at` | TTL артефакта (обычно +7d) |
| `active_revision`, `raw_high_watermark*` | Согласованность с snapshot/syslog tip |
| `template_key` / `parser_version` / `timezone` | Контекст устройства |

Контракт API — [exports.md](exports.md).

### `system_runtime_settings`

Одна строка `id=1`, документ JSONB `settings` (группы `projection`, `coverage`,
`voipmonitor`, `platform`, `containers`). Каталог ключей —
[auth-and-ui.md](auth-and-ui.md#параметры-runtime).

### Projection / reconciliation queues

`custom_projection_jobs`, `custom_projection_watermarks` — discovery, generation,
deadlines, leases, cursors, cutover. `custom_reconciliation_jobs` (+ per-device
lease) — one-to-one assignment CDR↔AF. Аналогично dirty/job таблицы для
VoIPmonitor (см. миграции PG рядом с worker’ом).

### Retention / audit

Retention policies (4 класса) — API admin; reconcile hourly.
`audit_log` — действия пользователей.

---

## ClickHouse

### Immutable Syslog — `collector.syslog_messages`

| Колонка | Смысл |
|---------|--------|
| `event_id` | Стабильный ID с ingress |
| `device_id` | Резолв по original sender IP |
| `received_at` | Instant приёма (UTC µs) |
| `source_ip` / `source_port` | Оригинальный UDP peer |
| `transport` | Сейчас `udp` |
| `payload` | Точные байты datagram |
| `payload_sha256` | Lowercase hex digest |

`MergeTree`, partition monthly, order `(device_id, received_at, event_id)` —
keyset cursor API. **Нет** parser/category/RADIUS/AF колонок.
`GET …/syslog-messages` отвергает `category`; search только по payload.

### CDR

- `cdr_records` — typed Eltex + `raw_fields`;
- `cdr_time_interpretations` / `cdr_time_facts` — timezone interpretation;
- `satel_rtu_cdr` / `satel_rtu_cdr_time_facts` — header-driven Satel (отдельно от Eltex).

Raw файлы — MinIO, ссылка из `ingest_files`.

### Custom AntiFraud и coverage

Таблицы (ReplacingMergeTree + markers): `custom_radius_packets`,
`custom_radius_packet_members`, `custom_radius_exchanges`,
`custom_antifraud_calls`, `custom_antifraud_call_packets`, dirty buckets,
`cdr_antifraud_coverage`, `cdr_antifraud_assignments`,
`custom_radius_session_events`.

Active views (`*_current`) выбирают snapshot active marker; partial staged
невидимы. После `ADD COLUMN` views нужно recreate (миграция 028/029).

Matching: exact normalized Acct-Session-Id, затем unique H323 из реального CDR
field. Номера/время — supporting evidence only.

### VoIPmonitor — `cdr_voipmonitor_links`

Ключевые поля: `source_system`, `source_record_id`, Call-ID поля источника,
`voipmonitor_cdr_id`, `voipmonitor_call_id`, `voipmonitor_card_url`,
`match_status`, `match_method`, `match_score`, `match_evidence_json`,
`policy_revision`, `projection_seq`, `deleted`.
View: `cdr_voipmonitor_links_current`. Dirty: `voipmonitor_dirty_buckets`.

---

## MinIO object keys

| Префикс | Содержание | Lifecycle |
|---------|------------|-----------|
| `cdr/` | Immutable raw CDR | retention class `raw_cdr_archive` (7–1095d) |
| `exports/` | Async export artifacts | **7 дней** |

---

## Retention classes

| Класс | Цель |
|-------|------|
| `syslog` | только `syslog_messages` |
| `cdr` | Eltex CDR + time tables |
| `softswitch_cdr` | Satel RTU tables |
| `raw_cdr_archive` | MinIO `cdr/` |

Legacy class `derived` удалён. Диапазон дней: **7–1095**, default 1095.
Не цели: `ingest_files`, NATS, spools.
