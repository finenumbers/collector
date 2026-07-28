# VoIPmonitor CDR correlation

Collector matches ingested Eltex / Satel CDR records to VoIPmonitor CDRs and stores
deep-links in ClickHouse (`collector.cdr_voipmonitor_links`). Matching is gated by
global runtime `voipmonitor.enabled` (**Настройки → Параметры**) and per-device
`devices.voipmonitor_enabled`. Env `VOIPMONITOR_*` only seeds an empty DB.

**Axiom:** every SMG / softswitch CDR exists in VoIPmonitor. An empty VoIPmonitor
cell is a matcher coverage defect after both legs’ Call-IDs were tried via API —
not “call missing upstream”. Never invent a link.

## Phase 0 evidence (calltrace / WEB API)

From [VoIPmonitor WEB API](https://www.voipmonitor.org/doc/WEB_API):

| Fact | Implication for Collector |
|------|---------------------------|
| Official browser deep-link is `admin.php?cdr_filter={fcallid:"…"}` | Default card URL **must** use `fcallid` with the exact VM `callId` |
| Documented GUI filters include `fcallid`, `fdatefrom`, `fcaller`, … — **not** `fId` | `{fId:N}` is ignored → unrelated CDR list (production symptom) |
| `getVoipCalls` supports `callId`, `cdrId`, `caller`/`called`, time range | Exact match = API query by Call-ID; not hour-dump alone |
| `getShareURL` with `cdrId`/`callId` | Optional true card link when share is enabled on GUI |
| `cdrId` is for API/PCAP/recording, not undocumented `cdr_filter` keys | Store `cdrId` for evidence; link via `fcallid` or share URL |

Attach-time rewrite: stored legacy `{fId:…}` URLs are rewritten to `{fcallid:"…"}`
when `voipmonitor_call_id` is present (fixes UI without rematch).

## Algorithm

1. **Ingest dirty buckets** — hour jobs in Postgres / ClickHouse dirty buckets.
2. **Discover** — enabling a device fans out recent hours (`projection.lookback`).
3. **Bucket match (hybrid):**
   - **Hour fetch:** `getVoipCalls` over `[from-callIdWindow, to+callIdWindow]`
     in 15‑minute slices → in-memory Call-ID index (few API calls per hour).
   - **Stage 1 exact:** normalized Call-ID lookup in that index; multi-leg →
     `matched_exact` (not `ambiguous`).
   - **Miss probes:** only for Call-IDs absent from the hour index — targeted
     `getVoipCalls(callId=raw|lower|strip@host)` (stops on first hit).
   - **Stage 2 fallback (B2BUA):** number/IP scoring against the hour set; status
     `matched_fallback` only.
   - Unique VM `cdrId` per device-hour; hour-fetch failure fails the job (retry),
     does not write a batch of false `unmatched`.
4. **Deep-link:** official `{fcallid:"<vm.callId>"}` (+ optional date bound);
   optional `getShareURL` when `voipmonitor.useShareUrl=true`.
5. **Policy revision** — toggle `voipmonitor_enabled` bumps revision and rediscovers.

### Identity fields

| Source | Call-ID order for API | Numbers / IP |
|--------|----------------------|--------------|
| Eltex SMG | `incoming_sip_call_id`, `outgoing_sip_call_id` | in/out CgPN·CdPN; in/out IP |
| Satel RTU | `out_leg_call_id`, `src_out_leg_call_id`, `in_leg_call_id`, `src_in_leg_call_id`, then conf IDs | bill/in/out ANI·DNIS; sig IPs |

## Statuses

| Status | Meaning |
|--------|---------|
| `matched_exact` | API Call-ID hit; VM `callId` equals a source Call-ID (raw or normalized) |
| `matched_fallback` | Call-ID miss; verified number/IP heuristic |
| `ambiguous` | Fallback candidates too close (margin); no URL |
| `unmatched` | Gates failed; evidence has `miss_reason` |
| `pending` | Reserved |

## Runtime settings (live tuning)

Edit in **Настройки → Параметры** (`PATCH /api/system/runtime-settings`).
Env `VOIPMONITOR_*` only seeds PostgreSQL when the settings row is empty.

| Runtime key | Default | Role |
|-------------|---------|------|
| `voipmonitor.enabled` | `false` | Start match worker |
| `voipmonitor.apiUrl` | | GUI origin; `/php/api.php` appended |
| `voipmonitor.user` / `password` | | API credentials |
| `voipmonitor.guiUrl` | | Base for `fcallid` deep-links |
| `voipmonitor.cardUrlTemplate` | empty → official `fcallid` | Opt-in custom template (do **not** use `{fId:…}`) |
| `voipmonitor.callIdWindow` | `30m` | Pad for Call-ID API search |
| `voipmonitor.fallbackWindow` | `2m` | Heuristic time gate |
| `voipmonitor.fallbackWindowMax` | `10m` | Expand once on clock skew |
| `voipmonitor.minScore` | `60` | Fallback floor |
| `voipmonitor.disambiguityMargin` | `8` | Fallback winner margin |
| `voipmonitor.numberSuffixLen` | `10` | Primary suffix (+1/+2 tried) |
| `voipmonitor.rateLimitPerSec` | `5` | API throttle |
| `voipmonitor.useShareUrl` | `false` | Prefer `getShareURL(cdrId)` when share enabled |

Discover lookback uses shared `projection.lookback` (same settings document).

## Acceptance checks (post-deploy)

```sql
-- New links must not use undocumented fId filters
SELECT count() FROM collector.cdr_voipmonitor_links_current
WHERE match_status IN ('matched_exact','matched_fallback')
  AND (voipmonitor_card_url LIKE '%fId:%' OR voipmonitor_card_url LIKE '%fId%3A%');

-- Exact rows must carry a VM Call-ID (for fcallid)
SELECT count() FROM collector.cdr_voipmonitor_links_current
WHERE match_status='matched_exact' AND voipmonitor_call_id='';
```

Manual: open 20 Fixer/MTS links — filtered list must show the **same** Call-ID /
participants as the SMG/RTU row (not an unrelated feed). Toggle correlation
off→on after upgrade to rematch; attach-time rewrite already repairs legacy `fId`
URLs when `voipmonitor_call_id` is present.

## Miss reasons

| `miss_reason` | Meaning |
|---------------|---------|
| `call_id_not_in_index` | Source Call-IDs tried via API; 0 hits |
| `empty_callid_and_weak_signal` | No Call-ID and weak number/IP |
| `fallback_below_threshold` | Heuristic / verify failed |
| `fallback_ambiguous` | Two heuristics within margin |
| `assigned_elsewhere` | VM `cdrId` taken by stronger match |
| `no_candidates_in_window` | No VM rows in fallback window |
| `api_error` | VoIPmonitor API failure |
