# Словарь данных SMG-1016M 3.410

## Время

`received_at` — UTC instant приёма datagram Collector. Raw wall clock из Eltex/RFC3164
и CDR хранится отдельно от canonical `event_time_utc`/`setup_time_utc`.
`source_timezone`, `source_utc_offset_minutes` и `timezone_revision` доказывают,
каким правилом выполнена интерпретация. `syslog_facts` и `cdr_time_facts` имеют revision
в ключе; API читает только атомарно активированную revision и возвращает одновременно
UTC RFC3339 и локальный RFC3339 с offset. UI не зависит от timezone браузера.

Для каждого SMG-1016M `source_timezone` CDR и Syslog равен IANA timezone из настроек
этого устройства. Одинаковые цифры wall clock от SMG в разных поясах соответствуют
разным canonical UTC instant, но в UI сохраняется время каждого конкретного SMG.

## Нормативные источники

- Eltex «SMG-1016M/2016/3016/3116. Руководство пользователя, ПО 3.410.0», разделы
  Syslog 4.1.22.3/4.2.2.52, CDR 4.1.8.1.2–4.1.8.1.5 и AntiFraud;
- Eltex «Подключение шлюзов SMG к ИС АнтиФрод по протоколу RADIUS»;
- официальный Eltex RADIUS dictionary.

Документация описывает release 3.410.0, но не исчерпывающую грамматику debug-трасс
конкретного build. Недокументированный payload не интерпретируется предположительно:
он сохраняется и получает `unknown`/`partial`.

## CDR

Парсер использует emitted field-name row. Если она отключена, применяется сохранённый в карточке устройства ordered profile. Исходная пара `имя → значение` всегда остаётся в `raw_fields`.

Основные группы:

- время: `Setup time`, `Connect time`, `Disconnect time`, `Duration`;
- завершение: `Release cause` (Q.850), `Call release info`, `Release side mark`;
- плечи: incoming/outgoing IP, type, description, E1 stream/channel;
- номера: incoming/outgoing CgPN/CdPN, redirecting number, numplan, NAI и original NAI;
- протоколы: incoming/outgoing SIP Call-ID, SS7 CIC, SS7 category, Calling party category (RUS), Global Callref;
- идентификаторы: `Sequence number`, `RADIUS Accounting-Session-Id`, `UniqueTag identifier`;
- сервисные: redirect/pickup/transfer marks, call/IVR recording paths, rejecting RADIUS server.

Семантика:

- setup — получение SETUP/INVITE;
- connect — CONNECT/200 OK; у неуспешного вызова может отсутствовать;
- duration — разговор после ответа, а не setup-to-disconnect;
- incoming numbers — до входящих модификаций; outgoing — после применённых модификаций;
- sequence — boot timestamp + номер CDR, уникален только в контексте устройства;
- Acct-Session-Id — значение, отправленное SMG в RADIUS;
- SIP Call-ID относится к конкретному плечу и может меняться на B2BUA;
- CIC/E1 быстро переиспользуются и не являются самостоятельными ключами;
- NAI — Nature of Address Indicator: `0 spare`, `1 subscriber`, `2 unknown`, `3 national`, `4 international`.

## Syslog envelope

Каждая принятая запись содержит:

- `event_id`, `device_id`, collector receive timestamp;
- source IP/port и transport;
- неизменённый payload и SHA-256;
- PRI/facility/severity, только если PRI реально присутствовал;
- detected envelope (`eltex`, `rfc3164`, `rfc3164-or-pri`, далее `rfc5424`);
- payload event time, component, message, parser version/status;
- typed/extracted attributes и category.

Категории:

- документированные trace switches: `alarms`, `call_trace`, `sip`, `isup`, `q931`,
  `radius`, `rtp`, `h323`, `hardware`, `ip_modules`, `ivr`, `ip_network`;
- отдельные журналы: `config_history`, `auth_log`, `system_journal`;
- диагностические: `ip_connections`, `unknown`.

Стандартные RFC3164-сообщения `application[pid]: component: message` сохраняют `application` и `process_id` в attributes. События `webapp: WEBS/SEC` относятся к `system_journal`. Любой неизвестный формат сохраняется без изменений и остаётся доступен одновременно в «Все Syslog» и «Нераспознанное».

Уровни Eltex `0–99` являются детализацией трассировки, а не RFC severity.

## RADIUS и AntiFraud

Операции:

- `save_call`/`number`: индикация исходящего вызова;
- `check_call`: верификация входящего вызова;
- `Accounting-Request`: длительность и завершение.

Сохраняются standard и vendor-specific attributes. Ключевые:

- `User-Name`, `Calling-Station-Id`, `Called-Station-Id`, `Acct-Session-Id`;
- `NAS-Port`, `NAS-Port-Type`, `Framed-IP-Address`, `Event-Timestamp`,
  `Acct-Delay-Time`, `Acct-Session-Time`;
- `h323-conf-id`, `h323-call-origin`, `h323-call-type`, redirect/generic number;
- `Eltex-AVPair`, `Cisco-AVPair`, включая `xpgk-request-type`,
  `xpgk-src-number-in/out`, `xpgk-dst-number-in/out`,
  `in-trunkgroup-label`, `out-trunkgroup-label`, `h323-remote-id`;
- setup/connect/disconnect, Q.850 disconnect cause и адрес RADIUS-сервера, когда они
  присутствуют в trace.

`radius_fragments` — один разобранный фрагмент/пакет, ссылающийся на исходный
`event_id`. `antifraud_lifecycles` — versioned lifecycle одного bounded context occurrence:
request/reply, операция, решение, сервер, latency/retry, accounting и список исходных
event IDs. Раздел «RADIUS» показывает полный технический поток; «АнтиФрод» показывает
только structured lifecycle с `xpgk-request-type` либо доказанным AntiFraud flow.

`call_assignments` содержит ровно одно текущее назначение lifecycle: linked
`cdr_record_id` либо явное состояние `ambiguous`/`orphan`, method, confidence, delta,
matched fields и reason. Повторная сверка той же dirty day bucket заменяет старое
назначение, поэтому stale links не накапливаются.

Решения:

- `check_call + Access-Accept` → `accept`, вызов продолжается;
- `check_call + Access-Reject` → `reject`, вызов завершается с Q.850 cause 21;
- timeout/недоступность всех серверов → `timeout_fail_open`, вызов продолжается;
- `number`/`save_call` — indication/registration; ответ не является решением о
  пропуске вызова и хранится как `informational`.

`Accounting-Request` завершает lifecycle данными длительности/причины; ожидается
`Accounting-Response`. Его отсутствие отмечается как неполный accounting.
