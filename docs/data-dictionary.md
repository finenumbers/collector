# Словарь данных SMG-1016M

Collector поддерживает две схемы обработки прошивки SMG-1016M: **`3.23.2`** и **`3.410`**.
Поле `devices.firmware` хранит именно схему (не полный build-number). Syslog использует
общий parser core и явный dialect profile из `template_key`; RADIUS/АнтиФрод используют
общую семантическую модель. Встроенные профили колонок CDR также различаются по схеме.

## Источники и ingest ledger

`devices.source_category` принимает `equipment` или `softswitch`.
`devices.template_key` является authoritative parser/archive contract; доступные
шаблоны публикует `GET /api/equipment-templates`. Для оборудования используются
`eltex-smg-1016m-3.410` и `eltex-smg-1016m-3.23.2`;
`satel-rtu-cdr-v1` (`Satel RTU`) — единственный шаблон софтсвитча и включает
отдельный typed CDR parser.

`ingest_files` хранит device-scoped SHA-256, исходное имя, размер, MinIO object key,
времена, состояние и применённые parser template/version. Durable replay повторно
обрабатывает сохранённый immutable object; список и скачивание всегда проверяют
одновременно `device_id` и `file_id`.

`devices.detection_*` сохранены для совместимости с ранее записанным provenance.
`ingest_files.replay_*` хранит durable очередь, parser/version, attempts и ошибку
отдельного архива.

`retention_policies.cdr` задаёт TTL typed CDR оборудования;
`retention_policies.softswitch_cdr` независимо задаёт TTL таблиц
`satel_rtu_cdr` и `satel_rtu_cdr_time_facts`. Политика `raw_cdr_archive`
остаётся общей для неизменяемых файлов оборудования и софтсвитчей в MinIO.

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

- Eltex «SMG-1016M/2016/3016. Руководство пользователя, версия ПО 3.23.2»,
  разделы трассировок, параметров Syslog, RADIUS и CDR;
- Eltex Documentation «3.410.0 Цифровые шлюзы SMG-1016M/2016/3016/3116»,
  разделы конфигурирования, трассировок, Syslog и CDR;
- Eltex «Подключение шлюзов SMG к ИС АнтиФрод по протоколу RADIUS»;
- официальный Eltex RADIUS dictionary.

Документация не даёт исчерпывающей грамматики debug-трасс конкретного build.
Недокументированный payload не интерпретируется предположительно: он сохраняется и
получает `unknown`/`partial`.

## CDR

Парсер использует emitted field-name row. Если она отключена, применяется встроенный
профиль схемы `firmware`: `3.23.2` — 50 колонок до `Called NAI original`;
`3.410` — те же плюс `Time in queue` и `Redirection type`.

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

### Satel RTU

Файл — UTF-8 CSV с разделителем `;`, quoting и строкой из 120 именованных колонок.
Парсер сопоставляет значения по header name, поэтому перестановка и добавление полей
не меняют схему. Duplicate/missing required header карантинирует файл; ошибка отдельной
строки сохраняется в ledger, но не блокирует вставку остальных строк. Полный
`raw_fields Map(String,String)` хранит исходные vendor значения.

`satel_rtu_cdr` не смешивается с Eltex `cdr_records`. Projection содержит provenance,
`cdr_id`, setup/connect/disconnect и term timestamps, ANI/DNIS/billing numbers,
src/dst/dial-plan routes, signaling/media endpoints, protocol/transport, conference и
call IDs, codecs, disconnect metadata, PDD/SCD, byte/packet/loss/jitter counters, LNP
поля и record type. Canonical timestamps хранятся в UTC вместе с source timezone,
offset и timezone revision.

Outcome определяется только фактом корректного `connect_time`: строка answered при
наличии connect и failed при его отсутствии. `disconnect_code_success` сохраняется как
vendor metadata и не определяет успешность — например, SIP 487 может иметь значение
`1`, хотя разговор не состоялся. Talk duration вычисляется как
`disconnect_time - connect_time`; vendor `elapsed_time` хранится отдельно.

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

Parser `eltex-smg-syslog-v15` использует общий envelope/classification core и сохраняет
`firmware_scheme`, `template_key` и `classification_result` в provenance. Dialect profiles
`3.23.2` и `3.410` ограничивают firmware-specific continuation. Core использует
**component-first** классификацию: `SIP` / `SIPT[…]` /
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

- допустимые RFC 4566 строки, включая `v=`/`o=`/`s=`/`c=`/`b=`/`t=`/`m=`/`a=`,
  → `sip`, `fragment_kind=sdp_line`; `b=AS:82` является bandwidth field;
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
Parser также публикует boundary facts `protocol_message_kind`, `direction`,
`message_name`, `callref`, `sip_call_id`, `packet_identifier` и
`construct_anchor_event_id`. Raw payload не склеивается: 1 datagram = 1 event.

`readable-syslog-v1` создаёт `syslog_constructs` и ordered
`syslog_construct_members`; `construct_id` стабилен от
`device_id + grouping_version + anchor_event_id`. Связи сохраняются в
`syslog_fragment_links` с method/confidence. Эта rollback-модель сохраняется, но при
`SYSLOG_CONSTRUCTS_ENABLED=false` не пополняется. Рабочий UI всегда читает плоскую
пагинацию raw-событий: одна строка соответствует одному исходному datagram.

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

Additive projection `antifraud_calls` / `antifraud_operations` / `antifraud_packets`
разделяет три identity. Call прежде всего определяется нормализованным
`h323-conf-id`, затем leg `Acct-Session-Id` и bounded `call_context`; несколько операций
могут принадлежать одному call. `number`, `save_call`, `check_call` и каждый accounting
occurrence остаются отдельными operations. RADIUS Identifier, retry и ordered
`attribute_keys` / `attribute_values` относятся только к packet. Packet стабилен от
raw construct anchor, поэтому replay того же event/burst заменяет ту же строку.
`current_antifraud_packets` и `current_antifraud_operations` используют `argMax` по
revision/version key; старые `antifraud_lifecycles` и `call_assignments` остаются
совместимым read model на время миграции.

Call-scoped API `GET /devices/{deviceID}/calls/{recordID}/antifraud-summary`
возвращает CDR, canonical call identity, leg session aliases, упорядоченные операции,
packet identifiers/codes/latency и correlation evidence. До active marker v16 endpoint
возвращает `projectionStatus=building` и только безопасные CDR facts, не смешивая v15/v16.

Строка CDR dump `server rejected: :0 (replied 0)` хранится как
`intrinsic_kind=cdr_dump_field`, `semantic_category=call_trace` и не означает
RADIUS `Access-Reject`. Настоящий reject требует RADIUS request/server evidence.

Public maps, export и UI удаляют `Password` / `User-Password`; immutable payload в
`raw_syslog` не изменяется. Operation-to-CDR correlation допускает несколько operations
к одному CDR. Несколько CDR с одним session без уникального временного преимущества
получают `ambiguous_session_collision`.

`call_assignments` содержит ровно одно текущее назначение lifecycle: linked
`cdr_record_id` либо явное состояние `ambiguous`/`orphan`, method, confidence, delta,
matched fields и reason. Повторная сверка той же dirty day bucket заменяет старое
назначение, поэтому stale links не накапливаются.

Решения:

- `check_call + Access-Accept` → `verification_accept`, вызов продолжается;
- `check_call + Access-Reject` → `verification_reject`; Q.850 сохраняется только при
  явном packet/CDR evidence и не синтезируется;
- timeout/недоступность всех серверов → `verification_fail_open`, вызов продолжается;
- `number`/`save_call` — indication/registration; ответ не является решением о
  пропуске вызова и хранится как `informational`.

`Accounting-Request` завершает lifecycle данными длительности/причины; ожидается
`Accounting-Response`. Его отсутствие отмечается как неполный accounting.

Parser `eltex-smg-syslog-v15` запускает durable historical replay через существующий
rebuild job. Пока replay идёт, новые v15 rows записываются в shadow tables, а API
продолжает читать legacy lifecycle. После достижения зафиксированного watermark worker
вставляет `active` marker в `parser_projection_state`; только после этого API атомарно
переключает конкретные device/timezone revision на v15 operations. Поэтому частично
перестроенная история и дубликаты между v14/v15 в AntiFraud list не показываются.
