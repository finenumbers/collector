# Корреляция вызовов и АнтиФрод

## Каноническая модель

CDR record — биллинговый факт одного логического/протокольного плеча. Пользовательский вызов может состоять из нескольких records при B2BUA, redirection, transfer, pickup, conference, IVR, SIP fork и alternate route.

RADIUS trace состоит из нескольких Syslog datagrams. Они сначала объединяются в
`antifraud_lifecycles` по device, timezone revision и bounded context occurrence.
Текущее one-to-one назначение хранится отдельно в `call_assignments`:
`cdr_record_id` либо explicit ambiguous/orphan, method, confidence, delta и matched
fields. Исходные записи не изменяются.

## Детерминированное правило

```text
device_id + normalize(RADIUS Accounting-Session-Id)
```

Нормализация удаляет whitespace и приводит регистр. Это единственное документированное прямое CDR↔AntiFraud RADIUS соответствие. `device_id` обязателен: RFC не гарантирует глобальную уникальность Acct-Session-Id между NAS/reboot.

Приход RADIUS или CDR пакетно ставит `device + timezone revision + UTC day` в durable
dirty queue. Worker повторно собирает весь малый day bucket идемпотентно, поэтому
CDR-first и RADIUS-first дают одно назначение без device-wide scan.

Когда Acct-Session-Id появился только в одном фрагменте transaction, все event IDs
этого же lifecycle связываются через evidence `call_context_transaction`.
Retransmissions остаются событиями доставки, но не становятся новыми вызовами.

## Дополнительные exact evidence

Автоматически разрешены только документированные точные значения:

1. incoming/outgoing SIP Call-ID в контексте устройства и ограниченного окна CDR;
2. SS7 Global Call Reference;
3. CDR `radius-rejected` как подтверждение блокирующего RADIUS server/reply.

Если exact ID недоступен, worker строит composite signature из всех вариантов CgPN/CdPN
до/после модификаций, точных incoming/outgoing route labels и исправленного event time.
Российские 10/11-значные номера канонизируются к `7XXXXXXXXXX`.

Внутри сигнатуры edges сортируются детерминированно по confidence, абсолютному time
delta и UUID. Связывается только unique best с margin; один CDR нельзя назначить двум
transactions. Один номер или округлённое время без route/второго номера недостаточны.

## Edge cases

- SIP fork: один ingress и несколько egress Call-ID; сохраняются все legs.
- Transfer: original/transferring/transferred records не склеиваются без transfer evidence.
- Redirect: участвуют incoming/outgoing/original/redirecting numbers.
- Route retry: trunk/IP/Call-ID меняются, Acct-Session-Id может сохраниться.
- Missing accounting: CDR остаётся полноценным unmatched record.
- Late events: используется embedded Event-Timestamp/Acct-Delay-Time, receive time только fallback.
- Source wall clock Syslog/CDR интерпретируется в IANA timezone устройства; UTC
  используется для хранения instant и matching, `received_at` остаётся отдельным фактом.
- Clock step/NTP: временное окно расширяется только после измерения observed offset.
- Reboot: sequence boot component сохраняется полностью.

## Coverage

В UI и метриках отдельно показываются:

- exact-linked;
- fallback-linked по каждому method;
- ambiguous candidates;
- unlinked CDR;
- RADIUS без CDR;
- unknown parser messages.

Для каждой AntiFraud transaction дополнительно фиксируются `complete`, `incomplete`,
`orphan` и `ambiguous`. Assignment строгий one-to-one; конфликтующие повторные
Acct-Session-Id разрешаются minimum delta либо остаются ambiguous, но не создают
несколько активных назначений.

Coverage-инвариант считается в направлении AntiFraud: `linked + ambiguous + orphan =
total AntiFraud`; число всех CDR не обязано совпадать с числом AntiFraud operations.
