# Корреляция с VoIPmonitor

Collector сопоставляет ingested Eltex / Satel CDR с CDR VoIPmonitor и хранит
deep-links в ClickHouse (`collector.cdr_voipmonitor_links`). Matching включается
глобально (`voipmonitor.enabled` в **Параметрах**) и per-device
(`devices.voipmonitor_enabled`). Env `VOIPMONITOR_*` — только seed пустой БД.

**Аксиома:** каждый CDR SMG/softswitch есть в VoIPmonitor. Пустая ячейка
VoIPmonitor после попыток Call-ID по API — **дефект покрытия matcher’а**, а не
«звонка нет upstream». Ссылки не выдумывать.

Онбординг и runtime — [deployment.md](deployment.md), [auth-and-ui.md](auth-and-ui.md).

---

## Phase 0: evidence (WEB API)

По [VoIPmonitor WEB API](https://www.voipmonitor.org/doc/WEB_API):

| Факт | Следствие |
|------|-----------|
| Официальный deep-link: `admin.php?cdr_filter={fcallid:"…"}` | Card URL **обязан** использовать `fcallid` с точным VM `callId` |
| GUI filters: `fcallid`, `fdatefrom`, … — **не** `fId` | `{fId:N}` игнорируется → чужой список CDR |
| `getVoipCalls`: `callId`, `cdrId`, caller/called, time | Exact = запрос по Call-ID |
| `getShareURL` | Опционально при включённом share на GUI |
| `cdrId` — для API/PCAP, не для недокументированных `cdr_filter` ключей | Хранить `cdrId`; линковать через `fcallid` или share |

Attach-time rewrite: legacy `{fId:…}` → `{fcallid:"…"}` при наличии
`voipmonitor_call_id` (чинит UI без rematch).

---

## Алгоритм

1. **Ingest dirty buckets** — часовые jobs в PG / CH dirty buckets.
2. **Discover** — enable устройства разворачивает недавние часы (`projection.lookback`).
3. **Bucket match (hybrid):**
   - **Hour fetch:** `getVoipCalls` по `[from−callIdWindow, to+callIdWindow]`
     слайсами 15m → in-memory Call-ID index.
   - **Stage 1 exact:** normalized Call-ID; multi-leg → `matched_exact` (не `ambiguous`).
   - **Miss probes:** только для Call-ID вне hour index —
     `getVoipCalls(callId=raw|lower|strip@host)`, stop on first hit.
   - **Stage 2 fallback (B2BUA):** scoring number/IP → только `matched_fallback`.
   - Unique VM `cdrId` на device-hour; сбой hour-fetch валит job (retry),
     не пишет пачку ложных `unmatched`.
4. **Deep-link:** `{fcallid:"<vm.callId>"}` (+ optional date); опционально
   `getShareURL` при `voipmonitor.useShareUrl=true`.
5. **Policy revision** — toggle `voipmonitor_enabled` bump’ает revision и rediscover.

### Identity fields

| Источник | Порядок Call-ID для API | Numbers / IP |
|----------|-------------------------|--------------|
| Eltex SMG | `incoming_sip_call_id`, `outgoing_sip_call_id` | in/out CgPN·CdPN; in/out IP |
| Satel RTU | `out_leg_call_id`, `src_out_leg_call_id`, `in_leg_call_id`, `src_in_leg_call_id`, затем conf IDs | bill/in/out ANI·DNIS; sig IPs |

---

## Статусы

| Status | Смысл |
|--------|--------|
| `matched_exact` | Hit по Call-ID; VM `callId` = source Call-ID (raw/normalized) |
| `matched_fallback` | Call-ID miss; прошла number/IP heuristic |
| `ambiguous` | Fallback кандидаты слишком близко (margin); без URL |
| `unmatched` | Gates failed; в evidence есть `miss_reason` |
| `pending` | Reserved |

---

## Runtime (live)

Правка в **Настройки → Параметры**. Ключи `voipmonitor.*` —
см. [auth-and-ui.md](auth-and-ui.md#параметры-runtime).

| Ключ | Default | Роль |
|------|---------|------|
| `enabled` | `false` | Старт match worker |
| `apiUrl` | | GUI origin; `/php/api.php` append |
| `user` / `password` | | API credentials |
| `guiUrl` | | База для `fcallid` |
| `cardUrlTemplate` | empty → official `fcallid` | Не использовать `{fId:…}` |
| `callIdWindow` | `30m` | Pad поиска Call-ID |
| `fallbackWindow` | `2m` | Heuristic time gate |
| `fallbackWindowMax` | `10m` | Один expand при clock skew |
| `minScore` | `60` | Fallback floor |
| `disambiguityMargin` | `8` | Margin победителя |
| `numberSuffixLen` | `10` | Primary suffix (+1/+2) |
| `rateLimitPerSec` | `5` | Throttle API |
| `useShareUrl` | `false` | Prefer share URL |

Discover lookback — общий `projection.lookback`.

---

## Проверки после deploy

```sql
SELECT count() FROM collector.cdr_voipmonitor_links_current
WHERE match_status IN ('matched_exact','matched_fallback')
  AND (voipmonitor_card_url LIKE '%fId:%' OR voipmonitor_card_url LIKE '%fId%3A%');

SELECT count() FROM collector.cdr_voipmonitor_links_current
WHERE match_status='matched_exact' AND voipmonitor_call_id='';
```

Вручную: 20 ссылок — в GUI тот же Call-ID / участники, что в строке SMG/RTU.
После upgrade: toggle off→on для rematch; rewrite уже чинит legacy `fId` URL.

---

## `miss_reason`

| Причина | Смысл |
|---------|--------|
| `call_id_not_in_index` | Source Call-ID через API → 0 hits |
| `empty_callid_and_weak_signal` | Нет Call-ID и слабый number/IP |
| `fallback_below_threshold` | Heuristic / verify failed |
| `fallback_ambiguous` | Два heuristic в пределах margin |
| `assigned_elsewhere` | VM `cdrId` занят более сильным match |
| `no_candidates_in_window` | Нет VM rows в fallback window |
| `api_error` | Сбой VoIPmonitor API |

---

## Типичные проблемы

| Симптом | Действие |
|---------|----------|
| Пустая ячейка при живом VM | Проверить enabled global+device, Call-ID в CDR, API credentials, rate limit |
| Чужой список в GUI | URL с `fId` — нужен `fcallid` / rematch |
| Много `ambiguous` | Поднять `disambiguityMargin` осторожно; проверить clock skew windows |
| Job retry loop | `api_error` / hour-fetch — сеть и GUI load |
