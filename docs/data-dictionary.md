# Словарь данных SMG-1016M 3.410

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

Категории: `alarms`, `call_trace`, `sip`, `isup`, `q931`, `ip_connections`, `ip_modules`, `radius`, `config_history`, `system_journal`, `unknown`.

Стандартные RFC3164-сообщения `application[pid]: component: message` сохраняют `application` и `process_id` в attributes. События `webapp: WEBS/SEC` относятся к `system_journal`. Любой неизвестный формат сохраняется без изменений и остаётся доступен одновременно в «Все Syslog» и «Нераспознанное».

Уровни Eltex `0–99` являются детализацией трассировки, а не RFC severity.

## RADIUS AntiFraud

Операции:

- `save_call`/`number`: индикация исходящего вызова;
- `check_call`: верификация входящего вызова;
- `Accounting-Request`: длительность и завершение.

Сохраняются standard и vendor-specific attributes. Ключевые: Calling/Called-Station-Id, Acct-Session-Id, Event-Timestamp, Acct-Delay-Time, session duration, setup/connect/disconnect, disconnect cause, trunk labels, gateway IP, redirect/original numbers.

Классификатор распознаёт RADIUS и без буквального слова `RADIUS`: по пакетам `Access-Request/Accept/Reject`, `Accounting-Request/Response`, атрибутам `Acct-Session-Id`, `Calling/Called-Station-Id` и VSA `xpgk-*`. В режиме Custom вкладка «АнтиФрод» показывает полный поток категории `radius`, не только события с уже извлечённым `xpgk-request-type`.

Результаты `check_call`: Access-Accept продолжает, Access-Reject завершает, timeout документирован как fail-open после исчерпания серверов/попыток. `save_call` не должен блокировать вызов.
