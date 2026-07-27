# Корреляция вызовов и Custom AntiFraud

## Каноническая модель

CDR record — биллинговый факт одного логического/протокольного плеча. Пользовательский
вызов может состоять из нескольких records при B2BUA, redirection, transfer, pickup,
conference, IVR, SIP fork и alternate route.

Custom AntiFraud строится только из immutable `collector.syslog_messages`. Фоновый
worker собирает RADIUS-пакеты и вызовы Custom AntiFraud в staged snapshots, а видимость
задаёт active marker. Сырые Syslog-строки не изменяются и не удаляются replay.

Разные нормализованные `Acct-Session-Id` всегда означают разные вызовы Custom AntiFraud.
Один CDR может быть связан только с одним таким вызовом; несколько exact-кандидатов
остаются `ambiguous`.

Custom call identity (строго):
- primary — `normalize(Acct-Session-Id)`;
- secondary — `h323-conf-id` только как link к уже известной session или lone `h323:…`;
- `calling`/`called`, SMG lane `[C…]`, `clg`/`cld` — только assembly и validation,
  никогда не образуют Call и не склеивают пакеты в один вызов;
- нет session и нет h323 → packet остаётся orphan/ambiguous, в Call не кладётся;
- семейство indication/verification задаёт только `xpgk-request-type`
  (`number`/`save_call` / `check_call`); ExplicitAF без типа не форсирует verification.

Attribute-dump строки (`Acct-Session-Id`, `Eltex-AVPair`, `xpgk-request-type`) обязательны
для полноценной сборки; они загружаются из `syslog_messages` даже без слова `RADIUS`
в payload.

## Детерминированное правило

```text
device_id + normalize(Acct-Session-Id)
```

Нормализация удаляет **все** whitespace и приводит регистр (одинаково в CDR,
Custom AF keys и reconciliation). Matching сначала проверяет exact normalized
`Acct-Session-Id` CDR ↔ Custom call. Если exact ID недоступен, допускается
unique H323 значение из реального поля CDR (`h323-conf-id` / эквивалент).

Номера A/B и время — **вторичная проверка** уже найденного primary-кандидата:
при расхождении assign запрещён (`number_mismatch` / `time_mismatch`). Номера и
время никогда не выбирают кандидата сами. Разные `Acct-Session-Id` никогда не
склеиваются в один Call.

Покрытие со стороны AF-call: `awaiting_cdr` → `expected` → `late` → `missing`,
либо `matched` / `ambiguous`. Неполная RADIUS-цепочка помечается
`chainCompleteness` (`complete` / `partial` / `minimal`).

`device_id` обязателен: RFC не гарантирует глобальную уникальность идентификаторов
между NAS/reboot. Любое множество из нескольких exact-кандидатов остаётся
`ambiguous`; временная сортировка используется только для детерминированного evidence.

Приход Syslog или CDR dirty-ит UTC-hour bucket. Worker идемпотентно пересобирает
малый bucket, поэтому CDR-first и AntiFraud-first дают одно и то же покрытие.
Toggle `antifraudEnabled` проверяется по PostgreSQL policy revision перед cutover:
disable пишет `not_applicable` coverage и оставляет raw Syslog нетронутым.

## Coverage states

В UI и метриках отдельно показываются состояния покрытия CDR ↔ Custom AntiFraud:

| State | Meaning |
| --- | --- |
| `expected` | CDR принят для устройства с включённым AntiFraud, связь ещё не подтверждена |
| `matched` | Unique exact link (Acct-Session-Id или unique H323) |
| `late` | Связь ещё не найдена после ожидаемого окна / lag |
| `missing` | После grace окно закрыто без unique match |
| `ambiguous` | Несколько exact-кандидатов; выбор запрещён |
| `not_applicable` | AntiFraud выключен для устройства |

Coverage-инвариант считается в направлении CDR с включённым AntiFraud: applicable
строки (`matched + expected + late + missing`) участвуют в SLO; `late + missing`
после grace не должны превышать 1%. Orphan/ambiguity пакеты Custom AntiFraud
учитываются отдельно в operational diagnostics.

## Edge cases

- SIP fork: один ingress и несколько egress Call-ID; сохраняются все CDR legs.
- Transfer / redirect: records не склеиваются без documented transfer evidence.
- Route retry: trunk/IP/Call-ID меняются, Acct-Session-Id может сохраниться.
- Missing accounting: CDR остаётся `expected` → `late`/`missing`, без синтетических пакетов.
- Late events: используется embedded Event-Timestamp/Acct-Delay-Time; receive time только fallback.
- Source wall clock CDR интерпретируется в IANA timezone конкретного SMG.
  Canonical UTC — внутренний instant для matching; UI/API/export показывают время
  устройства, `received_at` Syslog остаётся отдельным техническим фактом.
- Reboot: sequence/boot component сохраняется в provenance, но не создаёт новый call
  без нового `Acct-Session-Id`.

## Операционная диагностика

Администратор открывает панель «Диагностика» (lazy `GET /api/system/diagnostics`):
глубина/lag очереди Custom projection, coverage SLO, orphans/ambiguity и очередь
export. Legacy category breakdown, lifecycle counters и v16 canary markers удалены.
