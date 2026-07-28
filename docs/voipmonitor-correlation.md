# VoIPmonitor CDR correlation

Collector matches ingested Eltex / Satel CDR records to VoIPmonitor CDRs and stores
deep-links in ClickHouse (`collector.cdr_voipmonitor_links`). Matching is gated by
global `VOIPMONITOR_ENABLED` and per-device `devices.voipmonitor_enabled`.

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
2. **Discover** — enabling a device fans out recent hours (`CUSTOM_PROJECTION_LOOKBACK`).
3. **Bucket match (hybrid):**
   - **Hour fetch:** `getVoipCalls` over `[from-CALLID_WINDOW, to+CALLID_WINDOW]`
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
   optional `getShareURL` when `VOIPMONITOR_USE_SHARE_URL=true`.
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

## Environment

| Variable | Default | Role |
|----------|---------|------|
| `VOIPMONITOR_ENABLED` | `false` | Start match worker |
| `VOIPMONITOR_API_URL` | | GUI origin; `/php/api.php` appended |
| `VOIPMONITOR_USER` / `PASSWORD` | | API credentials |
| `VOIPMONITOR_GUI_URL` | | Base for `fcallid` deep-links |
| `VOIPMONITOR_CARD_URL_TEMPLATE` | empty → official `fcallid` | Opt-in custom template (do **not** use `{fId:…}`) |
| `VOIPMONITOR_CALLID_WINDOW` | `30m` | Pad for Call-ID API search |
| `VOIPMONITOR_TIME_SKEW` | alias → `CALLID_WINDOW` | Deprecated |
| `VOIPMONITOR_FALLBACK_WINDOW` | `2m` | Heuristic time gate |
| `VOIPMONITOR_FALLBACK_WINDOW_MAX` | `10m` | Expand once on clock skew |
| `VOIPMONITOR_MIN_SCORE` | `60` | Fallback floor |
| `VOIPMONITOR_DISAMBIGUITY_MARGIN` | `8` | Fallback winner margin |
| `VOIPMONITOR_NUMBER_SUFFIX_LEN` | `10` | Primary suffix (+1/+2 tried) |
| `VOIPMONITOR_RATE_LIMIT_PER_SEC` | `5` | API throttle |
| `VOIPMONITOR_USE_SHARE_URL` | `false` | Prefer `getShareURL(cdrId)` when share enabled |

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
