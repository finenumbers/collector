# Security and performance operating contract

## ClickHouse admission

Every production query is classified as `interactive`, `export`,
`custom_replay`, `custom_reconcile`, `ingest`, or `diagnostics`. The weighted
process-wide admission budget defaults to 8. Interactive waiters are selected
before background waiters, cancellation removes a waiter without leaking
capacity. A dedicated PostgreSQL advisory lock permits only one `export` or
`custom_replay` across all split-role processes, while the local heavy lease
prevents overlap inside a process. Queries receive a generated query ID, a class-only log comment,
execution timeout, thread and memory limits, and result row/byte limits. Query
text, filter values, and credentials are never emitted by diagnostics.

Lock order is:

1. workload admission;
2. device write/purge lock;
3. PostgreSQL transaction or ClickHouse operation.

Code must never wait for admission while holding a device lock. Custom
projection acquires its cutover lease before `LockDeviceWrites`; tests enforce
this ordering.

## Roles

`COLLECTOR_ROLE=app` remains the all-in-one default. Split deployments use:

- `api-ingest`: HTTP, authenticated API/downloads, NATS raw consumer and CDR watcher;
- `export`: exactly the asynchronous export worker;
- `maintenance`: custom projection/replay, reconciliation and retention;
- `ingress`: the existing source-preserving host-network UDP edge.

Compose exposes the split services under the `split` profile. Start them with
`docker compose --profile split up --scale collector=0`; running the default
`collector` at the same time would intentionally be rejected operationally
because it duplicates ownership. CPU and memory limits are configurable per
role. Separate ClickHouse usernames/passwords can be supplied after operators
provision corresponding least-privilege users and quotas.

Runtime settings PATCH is applied immediately in the API process and every
long-lived `api-ingest` / `export` / `maintenance` process polls PostgreSQL
(~2s) to hot-apply the same document locally (projection gate, worker
fingerprints, ClickHouse admission capacity, container-limits env). Split
`api-ingest` does not run the export worker in-process; dashboard and create-job
liveness use `export_jobs` heartbeats instead of a local Health probe.

## Secret handling and raw Syslog risk

The server recognizes Password/User-Password, CHAP, digest/preimage,
authenticator, token, credential, authorization, API/private keys, shared
keys/secrets, and secret-like vendor AVPair keys. The immutable
`syslog_messages` payload is preserved byte-for-byte in ClickHouse so its
stored SHA-256 remains verifiable. Redaction is enforced when building DTOs,
exports, errors, frontend displays, and derived projections.

Authenticated viewers continue to see raw Syslog rows for their selected
device, but displayed payload has recognized secrets removed.
Payload text remains operationally sensitive because unknown vendor formats,
phone numbers, topology, and identifiers can still be present. Exports remain
authenticated and device-scoped and downloads are audited. There is no
unredacted download route. ClickHouse access therefore remains an
operator-only trust boundary and must use encrypted storage and least-privilege
credentials.

## Bounds and search safeguards

List pages are capped at 1,000. Payload substring and call searches require a
device-local date; asynchronous administrators may explicitly request
`allTime` search. Dated search exports are capped at 31 days and search text at
256 characters. Export pages default to 1,000 and are configurable from
100–5,000. Export progress checks cancellation between pages, and workload
admission permits one export/replay heavy lane.

Call cards cap packets, exchanges, members, attributes, attribute values and
approximately 2 MiB of JSON. Truncation is deterministic and reported through
`truncated` and `warnings`; call outcome and packet count are computed from the
full aggregate rather than the retained evidence.

## Diagnostics and staging SLO

`GET /api/system/diagnostics` is admin-only, lazy, cached for 30 seconds, and
coalesces concurrent refreshes under an independent 8-second context. It
reports workload active/waiting/admitted/duration/rejections, raw ingest
counters, projection queue depth/oldest/lag, calls/packets/orphans/ambiguity,
coverage states/SLO, and export queued/running/oldest.

CI verifies invariants rather than machine timing. Before promotion, replay a
fixed anonymized capture at expected peak plus 50% for 30 minutes and record:

- interactive p95 under 2 seconds and p99 under 5 seconds;
- zero admission leaks/deadlocks and bounded cancellation under 1 second;
- projection lag under 5 minutes after load stops;
- coverage late+missing at or below 1% after the configured grace;
- export/replay never overlap in the heavy lane;
- no container OOM, ClickHouse overcommit, or unbounded response.

Run the same capture and configuration for baseline and candidate, preserve
the diagnostics snapshots, and compare throughput and queue drain time. Do not
encode these staging timing thresholds as brittle shared-runner CI assertions.
