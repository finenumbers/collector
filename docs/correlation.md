# CDR coverage и Custom AntiFraud

## Каноническая модель

CDR record — биллинговый факт одного логического/протокольного плеча. Пользовательский
вызов может состоять из нескольких records при B2BUA, redirection, transfer, pickup,
conference, IVR, SIP fork и alternate route.

Custom AntiFraud строится только из immutable `collector.syslog_messages`. Фоновый
worker собирает RADIUS-пакеты и вызовы Custom AntiFraud в staged snapshots, а видимость
задаёт active marker. Сырые Syslog-строки не изменяются и не удаляются replay.

Логический вызов Custom AntiFraud = один нормализованный `h323-conf-id`. Несколько
`Acct-Session-Id` (ноги) с общим h323 входят в **один** Call / одну строку таблицы /
одну карточку. Без h323 identity падает на `Acct-Session-Id` (одна session = один Call).
Один CDR связывается только с одним logical call; несколько exact-кандидатов остаются
`ambiguous`.

Custom call identity (строго):
- primary — `normalize(h323-conf-id)` → logical call `h323:…`;
- fallback — `normalize(Acct-Session-Id)` → `session:…`, если h323 пуст;
- `calling`/`called`, SMG lane `[C…]`, `clg`/`cld` — только assembly и validation,
  никогда не образуют Call и не склеивают пакеты в один вызов;
- нет session и нет h323 → packet остаётся orphan/ambiguous, в Call не кладётся;
- семейство indication/verification задаёт только `xpgk-request-type`
  (`number`/`save_call` / `check_call`); ExplicitAF без типа не форсирует verification.

`final_decision` (верификация входящего по Eltex Custom):
- `blocked` — был `check_call` + Access-Reject;
- `allowed` — был `check_call` + Access-Accept;
- `unavailable` — был `check_call`, ответа нет / unavailable_fallback;
- `not_applicable` — `check_call` не было (исходящая индикация `save_call`/`number`
  и/или accounting без верификации — нормальный случай);
- `unknown` — `check_call` был, но ответ неоднозначен.

Колонка **«Статус»** в таблице АнтиФрод показывает RADIUS Access-исход
(`radiusOutcome`), не lifecycle call:
- `accept` / Accept — был `Access-Accept` / `Access-Response` / `decision=allow`
  (indication или `check_call`);
- `reject` / Reject — был `Access-Reject` / `decision=deny` (важнее Accept);
- `no_response` / Нет ответа — иначе.

Lifecycle `status` на уровне Call остаётся в API/JSON/tooltip: `unavailable_fallback`
только при timeout на **`check_call`**. Timeout индикации (`number`/`save_call`)
остаётся в timeline, но не поднимает Call в `unavailable_fallback` и не
противоречит `final_decision=not_applicable`.

Transcript карточки (канон, **одна строка на каждую RADIUS-попытку**):

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

Несколько indication/verification-попыток **не схлопываются**: unpaired /
вторая нога видны отдельным шагом с `no_response`. Отсутствующая фаза не
синтезируется. `Access-Response` Eltex отображается как `Access-Accept`.
Сырые packet-attempts остаются в AntiFraud JSON.

Accounting Stop нормализует `h323-setup/connect/disconnect-time`,
`h323-disconnect-cause` (Q.850), `Acct-Session-Time`, `Acct-Delay-Time`,
`Event-Timestamp`. `Acct-Terminate-Cause` хранится отдельно и не подменяет Q.850.

Attribute-dump строки (`Acct-Session-Id`, `Eltex-AVPair`, `xpgk-request-type`) обязательны
для полноценной сборки; они загружаются из `syslog_messages` даже без слова `RADIUS`
в payload.

## Детерминированное правило

```text
device_id + normalize(h323-conf-id)   # если h323 есть
device_id + normalize(Acct-Session-Id) # иначе
```

Нормализация удаляет **все** whitespace и приводит регистр (одинаково в CDR,
Custom AF keys и reconciliation).

CDR identity keys (в порядке приоритета источника):

1. `normalize(RADIUS Accounting-Session-Id)` → `radius_session_id_normalized`
2. `normalize(UniqueTag identifier)` — Eltex-эквивалент, если отличается / session пуст
3. raw_fields с именем `*h323*conf*` (редко; в стандартном Eltex CSV колонки нет)

Matching (строго, без выбора по номерам/времени):

1. **Session pass:** любой CDR key ↔ AF `acct_session_id` / любая нога `acct_session_ids`
   (methods: `acct_session_id`, `unique_tag_as_session`).
2. **H323 pass** только если session pass дал 0 кандидатов: тот же набор keys ↔
   AF `h323_conf_id` (methods: `cdr_session_as_h323`, `h323_conf_id`).
   Так закрывается случай SMG 3.23.2, когда в CDR лежит conf-id-форма, а ноги AF
   другие: раздел АнтиФрод уже полный, а карточка Вызовы/CDR раньше не находила связь.

Номера A/B и время — **вторичная проверка** уже найденного primary-кандидата:
при расхождении assign запрещён (`number_mismatch` / `time_mismatch`). Номера и
время никогда не выбирают кандидата сами. Разные session **без** общего h323
никогда не склеиваются в один Call.

UI: на карточке из **Вызовы и CDR** лейблы coverage CDR-центричные
(«AntiFraud не найден» вместо «CDR опаздывает»); вход из АнтиФрод остаётся
AF-центричным.

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
| `matched` | Unique exact link (session leg, UniqueTag, или CDR key ↔ AF h323) |
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
