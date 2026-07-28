# Доступ и интерфейс

Bootstrap, роли, сессии и карта вкладок UI Collector.
Развёртывание стека — в [deployment.md](deployment.md); экспорт данных — в [exports.md](exports.md).

---

## Bootstrap

Токена `BOOTSTRAP_TOKEN` **нет**.

1. После первого deploy: `GET /api/bootstrap/status` → `{"bootstrapped":false}`.
2. UI предлагает создать первого администратора, либо `POST /api/bootstrap`
   с `username` (≥3) и `password` (≥12).
3. Когда есть хотя бы один активный admin, `bootstrapped=true` и endpoint закрыт.

Production отвергает дефолтные секреты (`collector:collector` в Postgres URL и т.п.) —
см. [deployment.md](deployment.md#5-секреты-и-first-bootstrap).

---

## Роли (RBAC)

| Роль | Возможности (суть) |
|------|---------------------|
| `admin` | Пользователи, устройства, retention, runtime settings, diagnostics admin-actions, cancel чужих export jobs |
| `analyst` | Чтение аналитики, создание экспортов, работа с устройствами в пределах API analyst |
| `viewer` | Только чтение списков/карточек; мутации и admin API — 403 |

Последнего активного администратора нельзя понизить, деактивировать или удалить
(last-admin guard).

Пароль: минимум **12** символов при bootstrap / create / update.

---

## Сессии, CSRF, lockout

| Параметр | Значение |
|----------|----------|
| Session TTL | **12 часов** (hardcoded) |
| Cookie | `HttpOnly`, `SameSite=Strict`, `Secure` при `SECURE_COOKIES=true` |
| CSRF | Для всех не-GET/HEAD/OPTIONS нужен заголовок `X-CSRF-Token` |
| CSRF token | Выдаётся при login / bootstrap / `GET /api/me` (ротация, если пустой) |
| Lockout | После **≥5** неудачных логинов — блокировка **15 минут**; успех сбрасывает счётчик |

За NPM с HTTPS оставляйте `SECURE_COOKIES=true`.

---

## Вкладки UI (операторская карта)

Точные подписи зависят от сборки UI; смысловые разделы:

| Раздел | Зачем |
|--------|--------|
| Syslog | Сырые сообщения устройства, поиск, sync/async экспорт |
| Вызовы и CDR | CDR Eltex / Satel, coverage badges, карточки |
| AntiFraud | Список вызовов Custom AF, карточка (RADIUS / H.323 / packets) |
| VoIPmonitor | Ссылки/статусы корреляции (если включено в Параметрах) |
| Источники / устройства | Онбординг SMG/Satel, Device Sign, FTP, `antifraudEnabled`, timezone |
| Пользователи | Только admin: роли, пароли, deactivate |
| Диагностика | Очереди projection/coverage/export, per-device lag, requeue |
| Параметры | Runtime settings + лимиты контейнеров |
| Retention | 4 класса 7–1095 дней |

Coverage/AF семантика состояний — [correlation.md](correlation.md).
VoIPmonitor — [voipmonitor-correlation.md](voipmonitor-correlation.md).

---

## Диагностика

`GET /api/system/diagnostics` (admin, lazy load).

Смотрите в первую очередь:

- `projectionDevices[]` — watermark lag, failed, `lastError`, classification gap;
- глобальные counters не заменяют per-device stall;
- export: queued / running / oldest age;
- coverage SLO / orphans / ambiguity.

Requeue failed projection для устройства:
`POST /api/devices/{deviceID}/projection/requeue-failed` (admin).

Типичный workflow catch-up — [deployment.md §14](deployment.md#14-canary-и-catch-up).

---

## Параметры (runtime)

`GET` / `PATCH /api/system/runtime-settings` — только admin.
После первого boot **UI/DB авторитетен**; переменные `.env` — seed пустой БД.

### `projection`

| Ключ | Смысл (default-ориентир) |
|------|---------------------------|
| `enabled` | Включить Custom projection worker |
| `lookback` | Горизонт назад (`24h`) |
| `batchSize` | Размер batch (`128`) |
| `maxEvents` | Потолок событий на окно (`50000`) |
| `threads` | Потоки CH replay (`2`) |
| `maxMemoryBytes` | Память replay (`256MiB`) |
| `sleep` | Пауза цикла (`1s`) |
| `lease` | Lease job (`2m`) |
| `responseTimeout` | Таймаут ответа |
| `pairingHorizon` | Горизонт pairing (`5m`) |
| `retryHorizon` | Горизонт retry (`168h`) |
| `assemblyIdle` | Idle assembly |

### `coverage`

| Ключ | Default-ориентир |
|------|------------------|
| `expectedGrace` | `5m` |
| `lateThreshold` | `5m` |
| `missingTerminal` | `30m` |
| `retryHorizon` | `168h` |
| `workerSleep` | `5s` |

### `voipmonitor`

Включение, URL API/GUI, credentials, окна call-id/fallback, score/margin,
rate limit, `useShareUrl`, lease/sleep worker. Пароль в GET маскируется
(`passwordSet`).

### `platform`

| Ключ | Смысл |
|------|--------|
| `clickhouseAdmissionCapacity` | Параллельные heavy/interactive слоты CH (`8`) |
| `exportPageSize` | Размер страницы чтения экспорта (`1000`) |

### `containers`

CPU/RAM для api / export / maintenance / app. После PATCH скачайте
`container-limits.env` и recreate compose — см. [deployment.md §8](deployment.md#8-runtime-settings-и-лимиты-контейнеров).

---

## Типичные ошибки

| Симптом | Причина |
|---------|---------|
| 403 на PATCH settings | Роль не `admin` |
| CSRF failed | Нет/устарел `X-CSRF-Token` после долгой вкладки — обновите `/api/me` |
| Locked out | 5 неверных паролей → ждите 15 минут |
| Bootstrap снова открыт | Нет активных admin в БД (после плохого restore) |
| Параметры «не из .env» | Ожидаемо: seed уже применён, дальше только UI |
