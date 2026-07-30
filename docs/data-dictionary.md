# Collector data dictionary

## PostgreSQL control plane

`devices.antifraud_enabled` is the sole AntiFraud mode switch.
`antifraud_policy_revision` changes on every toggle. `custom_projection_jobs`
and `custom_projection_watermarks` provide durable discovery, generation-aware
per-hour replay, explicit deadlines, leases, cursors, cutover, and rollback
provenance. `custom_reconciliation_jobs` and its per-device lease serialize
one-to-one assignment across deployment instances. The legacy `antifraud_mode`
column and `syslog_parser_rebuild_jobs` table are removed by migration 017.

`ingest_files` is the immutable CDR archive ledger. `export_jobs` is the
durable asynchronous export queue. Users, sessions, retention policies, and
audit records remain control-plane data.

## Immutable Syslog

`collector.syslog_messages` is the only persisted Syslog model in this
foundation:

- `event_id UUID`: stable ID created at ingress;
- `device_id UUID`: source resolved from the original sender IP;
- `received_at DateTime64(6, 'UTC')`: collector receive instant;
- `source_ip IPv6` and `source_port UInt16`: original UDP peer;
- `transport LowCardinality(String)`: currently `udp`;
- `payload String`: exact datagram bytes;
- `payload_sha256 FixedString(64)`: lowercase hexadecimal digest.

The table is monthly-partitioned `MergeTree`, ordered by
`(device_id, received_at, event_id)`. This order is the API keyset cursor.
There are no parser, category, component, RADIUS, construct, correlation, or
AntiFraud columns. The Custom worker reads this immutable table and owns a
separate marker-selected projection.

`GET /api/devices/{deviceID}/syslog-messages` returns the same flat fields.
The endpoint rejects a `category` query parameter. Search applies only to
payload, with device/date predicates and bound query arguments.

## CDR

`collector.cdr_records` retains Eltex typed CDR and its immutable `raw_fields`.
`cdr_time_interpretations` and `cdr_time_facts` remain because CDR timezone
interpretation is independent of removed Syslog parsing.

`collector.satel_rtu_cdr` and `collector.satel_rtu_cdr_time_facts` retain the
header-driven Satel RTU model. The full vendor row remains in `raw_fields`.
Satel and Eltex tables are intentionally separate. Migration 031 adds
`bill_ani_operator`, `bill_dnis_operator`, `bill_ani_region`, and
`bill_dnis_region` from the PSTN lookup API (`operator` and `garTerritory`;
UI «Регион A/B» stores territory). Only numbers matching prefixes 73/74/78/79
are looked up; both operator and territory are required. Catch-up / `satel-enrich`
must fill historical gaps for those prefixes and will not advance past unresolved
eligible sides. Migration 032 adds
`remote_src/dst_geoip_iso`, `remote_src/dst_geoip_city`, and
`remote_src/dst_asn_org` from GeoIP lookup on Remote src/dst sig (host without
port). Tokens live in runtime settings UI; seed from env on empty DB; backfill
via `collector satel-enrich`.

Raw CDR files remain in MinIO and are referenced by `ingest_files`.

## Custom AntiFraud projection and CDR coverage

Migrations 024–025 add `custom_radius_packets`,
`custom_radius_packet_members`, `custom_radius_exchanges`,
`custom_antifraud_calls`, `custom_antifraud_call_packets`, projection state
and dirty buckets, plus `cdr_antifraud_coverage`,
`cdr_antifraud_assignments`, and reconciliation dirty buckets. Derived rows
are monthly-partitioned `ReplacingMergeTree(projection_seq)` records. Active
views select only the snapshot named by the active marker, so staged partial
snapshots are invisible.

Ordered redacted attributes, immutable event provenance, orphan/ambiguity
reasons, explanation codes, match method, evidence, delta, and reconciliation
version are retained. Matching uses exact normalized Acct-Session-Id first and
then a unique H323 value present in a real CDR field. Numbers and time are
supporting evidence only.

Migration 026 adds finalized current views for packet members, exchanges, and
call links plus `custom_radius_session_events`, the bounded authoritative index
used to recompute sessions spanning hours or days.

## Retention

- `syslog` controls only `syslog_messages`;
- `cdr` controls Eltex CDR and CDR time tables;
- `softswitch_cdr` controls Satel RTU tables;
- `raw_cdr_archive` controls the MinIO CDR prefix.

The legacy `derived` retention class is removed.
