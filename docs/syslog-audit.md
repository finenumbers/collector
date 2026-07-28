# Аудит Syslog Eltex SMG-1016M

> **Superseded for runtime contracts.** This document is a historical corpus /
> taxonomy audit from the legacy parser UI era. Live Syslog storage and ops
> contracts are immutable ClickHouse `syslog_messages` plus Custom AntiFraud
> coverage — see [data-dictionary.md](data-dictionary.md). Keep this file for
> fixture provenance and Eltex taxonomy notes only.

## Нормативные источники

- Eltex «SMG-1016M/SMG-2016/SMG-3016. Руководство пользователя,
  версия ПО 3.23.2»: настройки трассировок, Syslog, RADIUS и CDR.
- Eltex Documentation «3.410.0 Цифровые шлюзы
  SMG-1016M/SMG-2016/SMG-3016/SMG-3116»: история изменений,
  конфигурирование устройства и приложения SMG.
- RFC 3164 (BSD Syslog), RFC 4566 (SDP), Q.850, Q.931, ISUP,
  SIP/SIP-T/SIP-I и официальный Eltex RADIUS dictionary.

Уровни трассировки Eltex `0–99` задают детализацию конкретной подсистемы и
не являются RFC Syslog severity.

## Проверенные входные файлы 2026-07-26

Исторический аудит. Имена файлов отражают legacy UI labels («Все Syslog» /
«Нераспознанное»), которые больше не являются продуктовыми вкладками; текущий
контракт — immutable `syslog_messages` и Custom AntiFraud coverage.

Файлы проверены по внутренней XLSX schema, каждой строке и SHA-256:

- `Eltex SMG-1016M 3.23.2 (Все Syslog).xlsx` (historical filename):
  SHA-256 `016bd2dd7f7d15f594d1cf236daf6c74d4e0eb048c8ffc3cbc3c3df032b11091`,
  5 152 data rows. Фактически это Eltex CDR export: 12 колонок от
  `Установка` до `UniqueTag`, без raw Syslog.
- `Eltex SMG-1016M 3.410 (Все Syslog).xlsx` (historical filename):
  SHA-256 `f868dac79d793811ff9704b5fc2205a69480030ef0a9e263bdae76035e0180cf`,
  376 data rows. Фактически это Eltex CDR export той же schema.
- `Eltex SMG-1016M 3.410 (Нераспознанное).xlsx` (historical filename):
  SHA-256 `b246a5375ba2f54075d53cbcbdb13483a245cb6415a70c991c08a8b6531d1b82`,
  27 data rows. Все строки имеют message `b=AS:82`, category `unknown`,
  component пустой и корректно разобранный Eltex trace envelope.

Первые два файла доказали ошибку export dataset, но не являются полными
Syslog-корпусами. После развёртывания исправленного exporter их необходимо
выгрузить повторно; до этого нельзя заявлять о статистически полном покрытии
всех production-сообщений обеих версий.

## Подтверждённая причина `b=AS:82`

`b=` — стандартное поле bandwidth в SDP по RFC 4566, а `AS:82` задаёт
application-specific bandwidth. До parser `eltex-smg-syslog-v15` bare SDP
allowlist включал `v/o/s/t/c/m/a`, но не включал `b`, поэтому envelope имел
status `parsed`, а semantic category оставалась `unknown`.

В профиле `3.410` bare SDP fields относятся к `sip` и получают
`fragment_kind=sdp_line`. Профиль `3.23.2` ожидает wrapped trace representation
(`##`) и не должен безусловно принимать отдельный `b=` без контекста.

## Нормативная taxonomy

- `sip`: SIP, SIP-T/SIP-I, SIP adapter, PBXIPC-SIP и SDP.
- `isup`: SS7/ISUP сообщения и PDU dump, если component не относится к SIP-T.
- `q931`: Q.931/DSS1.
- `radius`: RADIUS packets и AVP, включая AntiFraud evidence.
- `rtp`: RTP/RTCP media session/stream.
- `call_trace`: общий call state machine без более сильного protocol evidence.
- `alarms`: ALARM/ALARM-LED и alarm SNMP traps.
- `system_journal`, `config_history`, `auth_log`: эксплуатационные журналы.
- `hardware`, `ip_connections`, `ip_modules`, `ip_network`, `ivr`, `h323`:
  соответствующие подсистемы SMG.
- `unknown`: только сообщения без достаточного envelope/component/protocol
  evidence; raw payload при этом всегда сохраняется.

MGCP и H.248 не добавляются предположительно: их нет в предоставленном корпусе
и текущей подтверждённой конфигурации. Для них нужен отдельный документированный
пример Eltex trace.

## Обязательная повторная проверка после deployment

Исторический checklist периода legacy parser UI. Для текущего Custom rebuild:

1. Выгрузить dataset `syslog` (`syslog_messages`) для обоих template key.
2. Проверить export metadata, schema, row count и отсутствие ограничения 50 000.
3. При включённом `antifraudEnabled` сверить coverage states и operational diagnostics.
4. Обезличить representative bursts и сохранить как projection fixtures.
5. Перед upgrade выполнить `migration-preflight` и не продолжать без `copyVerified`.
