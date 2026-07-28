# VoIPmonitor CDR correlation

Collector matches ingested Eltex / Satel CDR records to VoIPmonitor CDRs and stores
deep-links in ClickHouse (`collector.cdr_voipmonitor_links`). Matching is gated by
global `VOIPMONITOR_ENABLED` and per-device `devices.voipmonitor_enabled`.

## Algorithm

1. **Ingest dirty buckets** — after a successful CDR insert, hour buckets from
   setup/connect/disconnect (fallback: ingested_at) are enqueued into Postgres
   `voipmonitor_match_jobs` and ClickHouse `voipmonitor_dirty_buckets`.
2. **Discover** — enabling a device (or toggling the flag) inserts a `discover` job
   that fans out recent hour buckets (lookback = `CUSTOM_PROJECTION_LOOKBACK`, default 24h).
3. **Bucket match** — the worker loads unmatched CDR candidates for the hour, then
   for each record:
   - exact / high-confidence SIP Call-ID lookup via VoIPmonitor `getVoipCalls`
     within `VOIPMONITOR_TIME_SKEW`;
   - fallback scoring (numbers, time, duration) when Call-ID is missing or ambiguous;
   - write a link row with status, method, score, and GUI card URL.
4. **Policy revision** — toggling `voipmonitor_enabled` bumps
   `voipmonitor_policy_revision`, cancels pending/running jobs, and on enable
   schedules a fresh `discover`.

## Statuses

| Status | Meaning |
|--------|---------|
| `matched_exact` | Single Call-ID hit (or verified Satel Call-ID) |
| `matched_fallback` | Heuristic / unverified match above `VOIPMONITOR_MIN_SCORE` |
| `ambiguous` | Multiple equally plausible hits |
| `unmatched` | No acceptable candidate |
| `pending` | Reserved / not yet finalized |

## Environment

| Variable | Default | Role |
|----------|---------|------|
| `VOIPMONITOR_ENABLED` | `false` | Start match worker (app/maintenance) |
| `VOIPMONITOR_API_URL` | | GUI origin (e.g. `https://vm.example.com`); `/php/api.php` is appended. Also accepts `…/php` or a full `…/php/api.php` |
| `VOIPMONITOR_USER` / `VOIPMONITOR_PASSWORD` | | API credentials |
| `VOIPMONITOR_GUI_URL` | | GUI base for card deep-links |
| `VOIPMONITOR_CARD_URL_TEMPLATE` | empty → `{gui_base}/admin.php?cdr_filter={fId:…}` | Deep-link template; default prefers numeric CDR id and URL-encodes `cdr_filter` |
| `VOIPMONITOR_TIME_SKEW` | `5s` | Call-ID search window around setup |
| `VOIPMONITOR_WORKER_SLEEP` | `5s` | Idle poll interval |
| `VOIPMONITOR_LEASE` | `2m` | Per-device job lease |
| `VOIPMONITOR_MIN_SCORE` | `60` | Minimum fallback score |
| `VOIPMONITOR_RATE_LIMIT_PER_SEC` | `5` | Client-side budget (reserved) |

Device flag: UI checkbox **Корреляция VoIPmonitor** (`voipmonitorEnabled`).
UI columns expose `voipmonitorCardUrl` (label prefers `voipmonitorCdrId`).
