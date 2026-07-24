# Словарь данных SMG-1016M

Collector поддерживает две схемы обработки прошивки SMG-1016M: **`3.23.2`** и **`3.410`**.
Поле `devices.firmware` хранит именно схему (не полный build-number). Syslog, RADIUS и
АнтиФрод пока разбираются общим парсером для обеих схем; отличается встроенный профиль
колонок CDR.

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

- Eltex «SMG-1016M/2016/3016/3116. Руководство пользователя» (ветки ПО 3.23 / 3.410),
  разделы Syslog и CDR;
- Eltex «Подключение шлюзов SMG к ИС АнтиФрод по протоколу RADIUS»;
- официальный Eltex RADIUS dictionary.

Документация не даёт исчерпывающей грамматики debug-трасс конкретного build.
Недокументированный payload не интерпретируется предположительно: он сохраняется и
получает `unknown`/`partial`.

## CDR

Парсер использует emitted field-name row. Если она отключена, применяется:

1. ручной `cdr_columns` из карточки SMG (если задан);
2. иначе встроенный профиль схемы `firmware` (`3.23.2` — 50 колонок до
   `Called NAI original`; `3.410` — те же плюс `Time in queue` и `Redirection type`).

Короткие data-строки (например 51 поле при заголовке 52) дополняются пустыми полями
справа. При настроенном `Device Sign` несовпадающий файл целиком помещается в
quarantine. Исходная пара `имя → значение` всегда остаётся в `raw_fields`.

Основные группы:

- время: `Setup time`, `Connect time`, `Disconnect time`, `Duration`;
- завершение: `Release cause` (Q.850), `Call release info`, `Release side mark`;
- плечи: incoming/outgoing IP, type, description, E1 stream/channel;
- номера: incoming/outgoing CgPN/CdPN, redirecting number, numplan, NAI и original NAI;
- протоколы: incoming/outgoing SIP Call-ID, SS7 CIC, SS7 category, Calling party category (RUS), Global Callref;
- идентификаторы: `Sequence number`, `RADIUS Accounting-Session-Id`, `UniqueTag identifier`;
- сервисные: redirect/pickup/transfer marks, call/IVR recording paths, rejecting RADIUS server;
- только схема `3.410`: `Time in queue`, `Redirection type`.

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
- detected envelope (`eltex`, `eltex-trace`, `eltex-config`, `rfc3164`,
  `rfc3164-or-pri`, далее `rfc5424`);
- payload event time, component, message, parser version/status;
- typed/extracted attributes и category.

Parser `smg-3.410-v12` (имя историческое; правила Syslog **общие** для схем прошивки
`3.23.2` и `3.410`) использует **component-first** классификацию: `SIP` / `SIPT[…]` /
`SIPT Proc` / `Port SIPT` / `PBXIPC-SIP` остаются в `sip` даже при тексте
`IAM-`/`ISUP`/`SS7` (SIP-I/SIP-T). Keyword `ISUP`/`IAM-` применяется только когда
SIP-компонент не распознан.

Envelope:

- Eltex trace `HH:MM:SS[.frac] [LEVEL] …` → `eltex-trace`, `parsed`;
- `CONFIG: …` сразу после `<hostname>` **без** timestamp → `eltex-config`, `parsed`,
  category `config_history` (диалект 3.410);
- RFC3164 / `last message repeated N times` — как раньше.

Фрагменты SMG (отдельные UDP datagram’ы) помечаются `trace_continuation` +
`fragment_kind` (`typed_hash`, `hash_detail`, `sdp`, `sdp_line`, `sdp_quote`, `codec`,
`avp`, `hex`, `dotted_hex`, `isup_optional`, `digest`, `rc_fragment`, `host_ip`,
`indented`, `empty`).

Диалект 3.410 (bare SDP без обёртки `##` 3.23.2):

- строки `v=`/`o=`/`s=`/`t=`/`c=`/`m=`/`a=` → `sip`, `fragment_kind=sdp_line`;
- обрывок `'` после `# SDP len (N): 'v=0` → `sip`, `fragment_kind=sdp_quote`;
- `\t\t 95.163.183.222` (HostIPlist) → `sip`, `fragment_kind=host_ip`.

Диалект 3.410 (SS7/ISUP PDU dump при включённой трассировке ISUP):

- dotted-hex `XX.XX.XX.…` (≥4 октета) → `isup`, `fragment_kind=dotted_hex`
  (**не** RADIUS continuous-hex);
- `\t\t[No optional params]` → `isup`, `fragment_kind=isup_optional`.

`ContinuationAssembler` индексирует parents по `device_id + call_context` и отдельные
radius/sip/isup burst без context. AVP/hex/digest наследуют RADIUS-родителя; `host_ip`,
bare SDP, `# cause`/`# requestID`/`# SDP` без `[C…]` — SIP-родителя (`sipBurst`, ≤2s);
`dotted_hex` / `isup_optional` — ISUP-родителя (`isupBurst`, ≤2s), без radius fallback.
Raw payload не склеивается: 1 datagram = 1 event. UI группирует списки по
`call_context` / `parent_event_id` и скрывает `empty_body`/hex/`dotted_hex`/digest
(SDP-строки оффера и `isup_optional` **не** скрываются).

Категории:

- документированные trace switches: `alarms`, `call_trace`, `sip`, `isup`, `q931`,
  `radius`, `rtp`, `h323`, `hardware`, `ip_modules`, `ivr`, `ip_network`;
- отдельные журналы: `config_history`, `auth_log`, `system_journal`;
- диагностические: `ip_connections`, `unknown`.

### Маппинг UI Syslog SMG 3.23.2 / 3.410 → категории Collector

Секции web-интерфейса SMG соответствуют категориям. В 3.410 добавлен отдельный тоггл
**«SIP-адаптер»** — отдельный dataset/nav в Collector **не** вводится: сообщения
`PBXIPC-SIP.*` и bare SDP уже попадают в `sip`.

| Секция SMG | Collector category |
|---|---|
| Traces → Аварии | `alarms` |
| Traces → Вызовы | `call_trace` |
| Traces → SS7-ISUP | `isup` |
| Traces → SIP | `sip` |
| Traces → SIP-адаптер (3.410) | `sip` (`PBXIPC-SIP`, SDP) |
| Traces → Q.931 | `q931` |
| Traces → IP-соединения | `ip_connections` |
| Traces → IP-субмодули | `ip_modules` |
| Traces → RADIUS | `radius` |
| История изменения конфигурации | `config_history` |
| Системный журнал / web / действия с записями разговоров | `system_journal`, `auth_log` |

Side-channels вне отдельных UI-тогглов (обязательны для пустого «Нераспознанного»):

- component `cdr` (rotate/rename `billing.cdr`) → `system_journal`;
- `alarm-led`, SNMP trap с `alarm-id` / `* TRAP *` → `alarms`; прочий SNMP → `system_journal`;
- RFC3164 `last message repeated N times` → `parsed`, category `system_journal`,
  attributes `repeat_suppressed=true`, `repeat_count=N` (без stateful link на предыдущее
  сообщение).
- `RADIUS server rejected: …` → component нормализуется в `RADIUS` (не длинная фраза).
- Пустое тело после `[Cxxxxxxx]` → `empty_body=true` (скрывается в UI как технический фрагмент).
- `SIPT Proc. …` с текстом `ISUP`/`SS7` → `sip` (component-first).

Стандартные RFC3164-сообщения `application[pid]: component: message` сохраняют `application` и `process_id` в attributes. События `webapp: WEBS/SEC` относятся к `system_journal`. Component извлекается только из allowlist Eltex-имён (`SIP`, `RADIUS`, `ALARM`, `mspc`, `Port SIPT`, `SIPT[…]`, `SIPT Proc`, `CONFIG`, …); двоеточие внутри timestamp (`HH:MM:SS`) и ложные component вроде `MAC_ext` не режут message. Любой неизвестный формат сохраняется без изменений и остаётся доступен одновременно в «Все Syslog» и «Нераспознанное».

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
