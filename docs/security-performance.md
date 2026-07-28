# Безопасность и производительность

Операционный контракт admission, redaction, bounds и staging SLO.
RBAC/сессии — [auth-and-ui.md](auth-and-ui.md); роли Compose —
[architecture.md](architecture.md); секреты production —
[deployment.md](deployment.md#5-секреты-и-first-bootstrap).

---

## ClickHouse admission

Каждый production-запрос классифицируется: `interactive`, `export`,
`custom_replay`, `custom_reconcile`, `ingest`, `diagnostics`.

Weighted process-wide budget по умолчанию **8**
(`platform.clickhouseAdmissionCapacity`). Interactive waiters выбираются раньше
background. Cancellation снимает waiter без утечки capacity.

Отдельный PostgreSQL advisory lock: только один `export` **или** `custom_replay`
на весь deployment; локальный heavy lease не даёт overlap внутри процесса.

Запросам назначаются query ID, class-only log comment, timeout, thread/memory
limits, row/byte limits. Текст запроса, фильтры и credentials diagnostics
**не** логирует.

Порядок блокировок:

1. workload admission;
2. device write/purge lock;
3. PostgreSQL transaction / ClickHouse operation.

Нельзя ждать admission, удерживая device lock. Custom projection берёт cutover
lease **до** `LockDeviceWrites`. Discover-курсоры — класс `custom_reconcile`
(non-heavy); hour snapshot write+activate — один `custom_replay`.

In-process ceilings (ориентир): Interactive **512 MiB** / 2 threads; CustomReplay
1 GiB / 1 thread; CustomReconcile 256 MiB; Export 512 MiB.

---

## Роли процессов

| Role | Владение |
|------|----------|
| `app` | All-in-one default |
| `api-ingest` | HTTP, downloads, NATS raw consumer, CDR watcher |
| `export` | Только async export |
| `maintenance` | Projection/replay, reconciliation, retention |
| `ingress` | Host-network UDP |

Split: `docker compose --profile split up --scale collector=0`. Не поднимать
рядом default `collector`. Опционально отдельные CH users/quotas после
провижининга least-privilege.

Runtime PATCH применяется сразу в API-процессе; long-lived роли полят PG (~2s)
и hot-apply документ локально. Split `api-ingest` не гоняет export in-process —
liveness смотрит heartbeats `export_jobs`.

---

## Секреты и риск raw Syslog

Redaction при сборке DTO, exports, errors, UI и derived projections распознаёт
Password/User-Password, CHAP, digest/preimage, authenticator, token, credential,
authorization, API/private keys, shared secrets, secret-like vendor AVPair.

Immutable `syslog_messages.payload` хранится byte-for-byte (SHA-256 верифицируем).
Authenticated viewers видят raw rows устройства, но displayed payload с
удалёнными распознанными секретами. Неизвестные vendor-форматы, номера и
топология всё равно чувствительны. Unredacted download route **нет**.
ClickHouse — operator-only trust boundary: шифрование диска, least privilege.

Production boot отклоняет: default CH/MinIO/SFTPGo passwords, `SECURE_COOKIES=false`,
`DATABASE_URL` с `://collector:collector@`.

---

## Bounds и search

| Ограничение | Значение |
|-------------|----------|
| List page | ≤ 1000 |
| Search | нужен device-local date; admin может `allTime` |
| Dated export range | ≤ 31 день |
| Search text | ≤ 256 символов |
| Export page size | 100–5000 (default 1000) |
| Sync export rows | ≤ 50 000 |
| Call card JSON | ~2 MiB + caps на packets/exchanges/attrs; truncation явная |

Export проверяет cancellation между страницами; heavy lane — один export/replay.

---

## Diagnostics и staging SLO

`GET /api/system/diagnostics` — admin-only, lazy, cache ~30s, coalesce под
отдельным 8s context. Отдаёт admission counters, raw ingest, projection
depth/lag/failed, orphans/ambiguity, coverage SLO, export queue.

CI проверяет инварианты, не хрупкий timing. Перед promotion: replay
анонимизированного capture на peak+50% / 30 минут и зафиксировать:

- interactive p95 ниже 2s, p99 ниже 5s;
- zero admission leaks/deadlocks; cancel ниже 1s;
- projection lag ниже 5 мин после снятия нагрузки;
- coverage late+missing ≤ 1% после grace;
- export/replay не overlap в heavy lane;
- нет container OOM / CH overcommit / unbounded response.

Сравнивайте baseline и candidate на одном capture; не кодируйте эти пороги
как brittle shared-runner CI asserts.
