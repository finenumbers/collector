# VoIPmonitor CDR correlation

Collector matches ingested Eltex / Satel CDR records to VoIPmonitor CDRs and stores
deep-links in ClickHouse (`collector.cdr_voipmonitor_links`). Matching is gated by
global `VOIPMONITOR_ENABLED` and per-device `devices.voipmonitor_enabled`.

**Axiom:** every SMG / softswitch CDR exists in VoIPmonitor. An empty VoIPmonitor
cell is a matcher coverage defect (wrong window, weak Call-ID normalize, false
`ambiguous`, thin number/IP coverage), not “call missing upstream”. Never invent a
link; residual `unmatched`/`ambiguous` rows carry `miss_reason` for triage.

## Algorithm

1. **Ingest dirty buckets** — after a successful CDR insert, hour buckets from
   setup/connect/disconnect (fallback: ingested_at) are enqueued into Postgres
   `voipmonitor_match_jobs` and ClickHouse `voipmonitor_dirty_buckets`.
2. **Discover** — enabling a device (or toggling the flag) inserts a `discover` job
   that fans out recent hour buckets (lookback = `CUSTOM_PROJECTION_LOOKBACK`, default 24h).
3. **Bucket match** — the worker loads unmatched CDR candidates for the hour, then:
   - fetches VoIPmonitor CDRs once for `[from - CALLID_WINDOW, to + CALLID_WINDOW]`
     (15-minute slices) and builds in-memory indexes;
   - **Stage 1 (exact):** normalized SIP Call-ID lookup. Multi-leg rows sharing the
     same Call-ID are disambiguated deterministically → `matched_exact` (not
     `ambiguous`);
   - **Stage 2 (fallback):** only when Call-ID is absent from the index — gated
     number suffix (10/11/12) + IP + time + duration scoring → `matched_fallback`;
   - unique VM `cdrId` assignment per device-hour; write link rows with evidence /
     `miss_reason`.
4. **Policy revision** — toggling `voipmonitor_enabled` bumps
   `voipmonitor_policy_revision`, cancels pending/running jobs, and on enable
   schedules a fresh `discover`.

## Statuses

| Status | Meaning |
|--------|---------|
| `matched_exact` | Normalized source Call-ID equals VM `callId` (multi-leg OK) |
| `matched_fallback` | Heuristic recovery when Call-ID was regenerated (B2BUA); never promoted to exact |
| `ambiguous` | Fallback candidates too close (margin); no URL |
| `unmatched` | Gates failed; evidence has `miss_reason` |
| `pending` | Reserved / not yet finalized |

## Environment

| Variable | Default | Role |
|----------|---------|------|
| `VOIPMONITOR_ENABLED` | `false` | Start match worker (app/maintenance) |
| `VOIPMONITOR_API_URL` | | GUI origin (e.g. `https://vm.example.com`); `/php/api.php` is appended. Also accepts `…/php` or a full `…/php/api.php` |
| `VOIPMONITOR_USER` / `VOIPMONITOR_PASSWORD` | | API credentials |
| `VOIPMONITOR_GUI_URL` | | GUI base for card deep-links |
| `VOIPMONITOR_CARD_URL_TEMPLATE` | empty → `{gui_base}/admin.php?cdr_filter={fId:…}` | Deep-link template; default prefers numeric CDR id and URL-encodes `cdr_filter` |
| `VOIPMONITOR_CALLID_WINDOW` | `30m` | Pad for hour VM fetch / Call-ID presence |
| `VOIPMONITOR_TIME_SKEW` | alias → `CALLID_WINDOW` | Deprecated compat alias |
| `VOIPMONITOR_FALLBACK_WINDOW` | `2m` | Heuristic time gate |
| `VOIPMONITOR_FALLBACK_WINDOW_MAX` | `10m` | Expand when numbers agree but clock skew is large |
| `VOIPMONITOR_WORKER_SLEEP` | `5s` | Idle poll interval |
| `VOIPMONITOR_LEASE` | `2m` | Per-device job lease |
| `VOIPMONITOR_MIN_SCORE` | `60` | Minimum fallback score |
| `VOIPMONITOR_DISAMBIGUITY_MARGIN` | `8` | Fallback winner margin |
| `VOIPMONITOR_NUMBER_SUFFIX_LEN` | `10` | Primary number suffix (also tries +1/+2) |
| `VOIPMONITOR_RATE_LIMIT_PER_SEC` | `5` | Client-side API throttle |

Device flag: UI checkbox **Корреляция VoIPmonitor** (`voipmonitorEnabled`).
UI columns expose `voipmonitorCardUrl` (label prefers `voipmonitorCdrId`).

## Evidence / miss reasons

`match_evidence_json` includes `stage`, `source_call_ids_normalized`, `selected`,
`runner_up`, `gates`, `vm_legs_with_same_call_id`, and when unlinked `miss_reason`:

| `miss_reason` | Meaning |
|---------------|---------|
| `call_id_not_in_index` | Source Call-IDs present but not in hour VM index |
| `empty_callid_and_weak_signal` | No Call-ID and insufficient number/IP signal |
| `fallback_below_threshold` | Best heuristic below `MIN_SCORE` / gates |
| `fallback_ambiguous` | Two heuristics within margin |
| `assigned_elsewhere` | Unique `cdrId` already taken by a stronger match |
| `no_candidates_in_window` | No VM rows in fallback time window |
| `api_error` | VoIPmonitor fetch failed |
