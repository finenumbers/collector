# CDR coverage и Custom AntiFraud

Канон модели вызова, matching и coverage. Операции canary/catch-up —
[deployment.md §14](deployment.md#14-canary-и-catch-up); пайплайн —
[architecture.md](architecture.md).

---

## Каноническая модель

CDR record — биллинговый факт одного логического/протокольного плеча. Пользовательский
вызов может состоять из нескольких records (B2BUA, redirect, transfer, pickup,
conference, IVR, SIP fork, alternate route).

Custom AntiFraud строится **только** из immutable `collector.syslog_messages`.
Фоновый worker собирает RADIUS-пакеты и вызовы в staged snapshots; видимость —
active marker. Сырые Syslog-строки replay не меняет и не удаляет.

Логический вызов Custom AntiFraud = один нормализованный `h323-conf-id`. Несколько
`Acct-Session-Id` (ноги) с общим h323 входят в **один** Call / одну строку /
одну карточку. Без h323 identity падает на `Acct-Session-Id` (одна session = один Call).
Один CDR связывается только с одним logical call; несколько exact-кандидатов →
`ambiguous`.

### Identity (строго)

- primary — `normalize(h323-conf-id)` → logical call `h323:…`;
- fallback — `normalize(Acct-Session-Id)` → `session:…`, если h323 пуст;
- `calling`/`called`, SMG lane `[C…]`, `clg`/`cld` — только assembly/validation,
  **никогда** не образуют Call и не склеивают пакеты;
- нет session и нет h323 → packet orphan/ambiguous, в Call не кладётся;
- семейство indication/verification задаёт только `xpgk-request-type`
  (`number` / `save_call` / `check_call`); ExplicitAF без типа не форсирует verification.

### `final_decision` (верификация входящего)

| Значение | Смысл |
|----------|--------|
| `blocked` | был `check_call` + Access-Reject |
| `allowed` | был `check_call` + Access-Accept |
| `unavailable` | был `check_call`, ответа нет / unavailable_fallback |
| `not_applicable` | `check_call` не было (исходящая индикация / accounting без верификации) |
| `unknown` | `check_call` был, ответ неоднозначен |

Колонка **«Статус»** в таблице АнтиФрод — это `radiusOutcome`, не lifecycle:

| Outcome | Смысл |
|---------|--------|
| `accept` | Access-Accept / Access-Response / `decision=allow` |
| `reject` | Access-Reject / `decision=deny` (важнее Accept) |
| `no_response` | иначе |

Lifecycle `status` в API/JSON/tooltip: `unavailable_fallback` только при timeout
на **`check_call`**. Timeout индикации (`number`/`save_call`) остаётся в timeline,
но не поднимает Call в `unavailable_fallback` и не спорит с
`final_decision=not_applicable`.

Прочие lifecycle: `blocked`, `ambiguous_indeterminate`, `verified`, `completed`,
`open`, `pending`.

### Transcript карточки (канон)

Одна строка на каждую RADIUS-попытку:

```text
CALL <primary_session>
A: <calling>
B: <called>

1) indication: save_call|number -> Access-Accept
2) indication: number -> no_response
3) verification: check_call -> Access-Accept|Access-Reject|no_response
4) accounting: Stop -> Accounting-Response

final_decision=allowed|blocked|unavailable|not_applicable|unknown
duration_sec=15
disconnect_cause_q850=10
```

Несколько indication/verification **не схлопываются**. Отсутствующая фаза не
синтезируется. `Access-Response` Eltex отображается как `Access-Accept`.

Accounting Stop нормализует `h323-setup/connect/disconnect-time`,
`h323-disconnect-cause` (Q.850), `Acct-Session-Time`, `Acct-Delay-Time`,
`Event-Timestamp`. `Acct-Terminate-Cause` хранится отдельно и не подменяет Q.850.

Attribute-dump строки (`Acct-Session-Id`, `Eltex-AVPair`, `xpgk-request-type`)
обязательны для сборки; читаются из `syslog_messages` даже без слова `RADIUS`
в payload.

---

## Детерминированное правило

```text
device_id + normalize(h323-conf-id)   # если h323 есть
device_id + normalize(Acct-Session-Id) # иначе
```

Нормализация удаляет **все** whitespace и приводит регистр (одинаково в CDR,
Custom AF keys и reconciliation).

### CDR identity keys (приоритет)

1. `normalize(RADIUS Accounting-Session-Id)` → `radius_session_id_normalized`
2. `normalize(UniqueTag identifier)` — если отличается / session пуст
3. raw_fields с именем `*h323*conf*` (редко; в стандартном Eltex CSV колонки нет)

### Matching (строго)

1. **Session pass:** любой CDR key ↔ AF `acct_session_id` / любая нога
   `acct_session_ids` (methods: `acct_session_id`, `unique_tag_as_session`).
2. **H323 pass** только если session pass дал 0 кандидатов: тот же набор keys ↔
   AF `h323_conf_id` (methods: `cdr_session_as_h323`, `h323_conf_id`).
   Закрывает SMG 3.23.2, когда в CDR conf-id-форма, а ноги AF другие.

Номера A/B и время — **вторичная проверка** уже найденного primary-кандидата:
при расхождении assign запрещён (`number_mismatch` / `time_mismatch`). Номера и
время никогда не выбирают кандидата. Разные session **без** общего h323
никогда не склеиваются.

UI: с карточки **Вызовы и CDR** лейблы coverage CDR-центричные
(«AntiFraud не найден» вместо «CDR опаздывает»); вход из АнтиФрод — AF-центричный.

Покрытие со стороны AF-call: `awaiting_cdr` → `expected` → `late` → `missing`,
либо `matched` / `ambiguous`. Неполная RADIUS-цепочка — `chainCompleteness`
(`complete` / `partial` / `minimal`).

Возрастные полосы на карточке AF (hardcoded в коде карточки, не runtime coverage
settings): `matched` → `ambiguous` → младше 5m `awaiting_cdr` → младше 10m
`expected` → младше 30m `late` → иначе `missing`.

`device_id` обязателен: RFC не гарантирует глобальную уникальность идентификаторов
между NAS/reboot. Несколько exact-кандидатов → всегда `ambiguous`.

Приход Syslog или CDR dirty-ит UTC-hour bucket. Worker идемпотентно пересобирает
bucket: CDR-first и AntiFraud-first дают одно покрытие. Toggle `antifraudEnabled`
проверяется по policy revision перед cutover: disable пишет `not_applicable`,
raw Syslog не трогает.

---

## Coverage states

| State | Смысл |
|-------|--------|
| `expected` | CDR принят, AF включён, связь ещё не подтверждена |
| `awaiting_cdr` | Со стороны AF: ждём CDR (ранняя полоса на карточке) |
| `matched` | Unique exact link (session / UniqueTag / CDR key ↔ AF h323) |
| `late` | Связь не найдена после ожидаемого окна |
| `missing` | После grace окно закрыто без unique match |
| `ambiguous` | Несколько exact-кандидатов; выбор запрещён |
| `not_applicable` | AntiFraud выключен для устройства |
| `unmatched` | UI-badge (в т.ч. VoIP/другие контексты); не путать с AF missing |

SLO: applicable (`matched + expected + late + missing`); после grace
`late + missing` ≤ 1%. Orphan/ambiguity пакеты — отдельно в Диагностике.

---

## Edge cases

- SIP fork: несколько egress Call-ID; все CDR legs сохраняются.
- Transfer / redirect: records не склеиваются без documented transfer evidence.
- Route retry: trunk/IP/Call-ID меняются, Acct-Session-Id может сохраниться.
- Missing accounting: CDR `expected` → `late`/`missing`, без синтетических пакетов.
- Late events: Event-Timestamp / Acct-Delay-Time; receive time — fallback.
- Wall clock CDR — IANA timezone устройства; canonical UTC — для matching;
  UI/export показывают время устройства; `received_at` Syslog — отдельный факт.
- Reboot: sequence/boot в provenance, новый Call только с новым session id.

---

## Операционная диагностика

Панель **Диагностика**: глубина/lag Custom projection, coverage SLO,
orphans/ambiguity, export queue. Per-device метрики важнее global lag.
Catch-up — [deployment.md](deployment.md#14-canary-и-catch-up).
