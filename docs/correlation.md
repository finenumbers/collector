# Корреляция вызовов и АнтиФрод

## Каноническая модель

CDR record — биллинговый факт одного логического/протокольного плеча. Пользовательский вызов может состоять из нескольких records при B2BUA, redirection, transfer, pickup, conference, IVR, SIP fork и alternate route.

Связь хранится отдельно в `call_event_links`: `cdr_record_id`, `event_id`, method, confidence, evidence и parser version. Исходные записи не изменяются.

## Детерминированное правило

```text
device_id + normalize(RADIUS Accounting-Session-Id)
```

Нормализация удаляет whitespace и приводит регистр. Это единственное документированное прямое CDR↔AntiFraud RADIUS соответствие. `device_id` обязателен: RFC не гарантирует глобальную уникальность Acct-Session-Id между NAS/reboot.

Корреляция выполняется в обе стороны:

- пришёл RADIUS после CDR — link создаёт Syslog worker;
- пришёл CDR после RADIUS — link создаёт CDR importer.

Retransmissions остаются событиями доставки, но не становятся новыми вызовами.

## Fallback-порядок

Следующие правила должны добавляться только с evidence и confidence:

1. UniqueTag/X-UniqueTag, если подтверждена передача в обоих источниках;
2. incoming/outgoing SIP Call-ID в контексте устройства и временного окна;
3. SS7 Global Call Reference;
4. trunk/link + CIC + interval overlap;
5. номера до/после модификаций + trunk labels + setup/connect/disconnect + duration + Q.850.

Номер телефона и округлённое время без дополнительных признаков не считаются связью.

## Edge cases

- SIP fork: один ingress и несколько egress Call-ID; сохраняются все legs.
- Transfer: original/transferring/transferred records не склеиваются без transfer evidence.
- Redirect: участвуют incoming/outgoing/original/redirecting numbers.
- Route retry: trunk/IP/Call-ID меняются, Acct-Session-Id может сохраниться.
- Missing accounting: CDR остаётся полноценным unmatched record.
- Late events: используется embedded Event-Timestamp/Acct-Delay-Time, receive time только fallback.
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

Порог автоматического fallback-link фиксируется после canary corpus; до этого кандидаты не склеиваются автоматически.
