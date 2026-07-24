ALTER TABLE collector.radius_events
    ADD COLUMN IF NOT EXISTS transaction_id UUID DEFAULT toUUID('00000000-0000-0000-0000-000000000000') AFTER device_id,
    ADD COLUMN IF NOT EXISTS call_context String DEFAULT '' AFTER transaction_id,
    ADD COLUMN IF NOT EXISTS is_antifraud UInt8 DEFAULT 0 AFTER call_context,
    ADD COLUMN IF NOT EXISTS decision LowCardinality(String) DEFAULT '' AFTER result,
    ADD COLUMN IF NOT EXISTS decision_reason String DEFAULT '' AFTER decision,
    ADD COLUMN IF NOT EXISTS event_timestamp Nullable(DateTime64(3, 'UTC')) AFTER decision_reason,
    ADD COLUMN IF NOT EXISTS acct_delay_seconds Nullable(UInt32) AFTER event_timestamp,
    ADD COLUMN IF NOT EXISTS accounting_status LowCardinality(String) DEFAULT '' AFTER acct_delay_seconds,
    ADD COLUMN IF NOT EXISTS completeness LowCardinality(String) DEFAULT 'fragment' AFTER accounting_status;

ALTER TABLE collector.cdr_records
    ADD COLUMN IF NOT EXISTS incoming_redirecting_number String DEFAULT '' AFTER outgoing_cdpn,
    ADD COLUMN IF NOT EXISTS outgoing_redirecting_number String DEFAULT '' AFTER incoming_redirecting_number,
    ADD COLUMN IF NOT EXISTS incoming_numplan String DEFAULT '' AFTER outgoing_redirecting_number,
    ADD COLUMN IF NOT EXISTS outgoing_numplan String DEFAULT '' AFTER incoming_numplan,
    ADD COLUMN IF NOT EXISTS calling_nai String DEFAULT '' AFTER outgoing_numplan,
    ADD COLUMN IF NOT EXISTS called_nai String DEFAULT '' AFTER calling_nai,
    ADD COLUMN IF NOT EXISTS incoming_e1_stream String DEFAULT '' AFTER called_nai,
    ADD COLUMN IF NOT EXISTS incoming_e1_channel String DEFAULT '' AFTER incoming_e1_stream,
    ADD COLUMN IF NOT EXISTS outgoing_e1_stream String DEFAULT '' AFTER incoming_e1_channel,
    ADD COLUMN IF NOT EXISTS outgoing_e1_channel String DEFAULT '' AFTER outgoing_e1_stream;

ALTER TABLE collector.call_event_links
    ADD COLUMN IF NOT EXISTS ambiguity UInt8 DEFAULT 0 AFTER confidence,
    ADD COLUMN IF NOT EXISTS candidate_reason String DEFAULT '' AFTER ambiguity;

CREATE TABLE IF NOT EXISTS collector.antifraud_transactions
(
    transaction_id UUID,
    device_id UUID,
    updated_at DateTime64(6, 'UTC'),
    first_event_at DateTime64(6, 'UTC'),
    last_event_at DateTime64(6, 'UTC'),
    call_context String,
    acct_session_id String,
    acct_session_id_normalized String,
    packet_identifier Nullable(UInt8),
    request_type LowCardinality(String),
    request_code LowCardinality(String),
    response_code LowCardinality(String),
    decision LowCardinality(String),
    decision_reason String,
    server_address String,
    retries UInt16,
    latency_ms Nullable(UInt32),
    calling_station_id String,
    called_station_id String,
    src_number_in String,
    dst_number_in String,
    src_number_out String,
    dst_number_out String,
    in_trunkgroup_label String,
    out_trunkgroup_label String,
    accounting_status LowCardinality(String),
    q850_cause Nullable(UInt16),
    is_antifraud UInt8,
    completeness LowCardinality(String),
    attributes Map(String, String),
    raw_event_ids Array(UUID),
    parser_version LowCardinality(String)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(first_event_at)
ORDER BY (device_id, transaction_id)
TTL toDateTime(first_event_at) + INTERVAL 36 MONTH DELETE;

CREATE TABLE IF NOT EXISTS collector.syslog_reprocess_ledger
(
    event_id UUID,
    parser_version LowCardinality(String),
    processed_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(processed_at)
ORDER BY (event_id, parser_version);

CREATE TABLE IF NOT EXISTS collector.call_correlation_candidates
(
    device_id UUID,
    cdr_record_id UUID,
    transaction_id UUID,
    method LowCardinality(String),
    confidence Float32,
    ambiguity UInt8,
    candidate_reason String,
    evidence Map(String, String),
    created_at DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (device_id, cdr_record_id, transaction_id, method);

ALTER TABLE collector.raw_syslog
UPDATE
    parser_version = 'smg-3.410-v5',
    category = multiIf(
        match(payload, '(?i)(?:webapp|webspp)(?:\\[[0-9]+\\])?:\\s*(?:WEBS|SEC)\\s*:') OR
            match(payload, '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+(?:WEBS|SEC)\\s*:'), 'system_journal',
        match(payload, '(?i)(?:\\]|\\.)\\s*(?:RADIUS|RC)\\s*[\\.:]|ACCESS-(?:REQUEST|ACCEPT|REJECT)|ACCOUNTING-(?:REQUEST|RESPONSE)|ACCT-SESSION-ID|XPGK-'), 'radius',
        match(payload, '(?i)SS7|ISUP|IAM-|RLC-'), 'isup',
        match(payload, '(?i)Q\\.931|Q931|DSS1'), 'q931',
        match(payload, '(?i)(?:\\]|\\.)\\s*(?:SIP|SIPT|PBXIPC-SIP)\\s*[\\.:]|\\bINVITE\\s+sip:|\\bCALL-ID\\s*[=:]'), 'sip',
        match(payload, '(?i)(?:\\]|\\.)\\s*H323\\s*[\\.:]'), 'h323',
        match(payload, '(?i)(?:\\]|\\.)\\s*(?:RTP|RTCP|RTP-CREATE)\\s*[\\.:]|\\bRTP\\s+(?:SESSION|STREAM|CONNECTION)'), 'rtp',
        match(payload, '(?i)(?:\\]|\\.)\\s*(?:HW|HARDWARE)\\s*[\\.:]'), 'hardware',
        match(payload, '(?i)(?:\\]|\\.)\\s*(?:SM-VP|SMVP|MSP)\\s*[\\.:]'), 'ip_modules',
        match(payload, '(?i)(?:\\]|\\.)\\s*IVR\\s*[\\.:]'), 'ivr',
        match(payload, '(?i)(?:\\]|\\.)\\s*IPNET\\s*[\\.:]'), 'ip_network',
        match(payload, '(?i)IP-CONN|CONN\\['), 'ip_connections',
        match(payload, '(?i)(?:^|[\\s:,])ALARMS?(?:$|[\\s:,])|АВАР'), 'alarms',
        match(payload, '(?i)CONFIG|COMMAND|USERLOG'), 'config_history',
        match(payload, '(?i)AUTHLOG|(?:\\]|\\.)\\s*AUTH\\s*[\\.:]'), 'auth_log',
        match(payload, '\\[C[A-Za-z0-9_-]+\\]') OR match(payload, '(?i)(?:^|[\\s:,])CALLS?(?:$|[\\s:,])|(?:^|[\\s:,])PORT\\s+[0-9]'), 'call_trace',
        match(payload, '(?i)^(?:<[0-9]{1,3}>)?[A-Z][a-z]{2}\\s+[0-9]{1,2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\\s+(?:\\S+\\s+)?[A-Za-z0-9_.-]+(?:\\[[0-9]+\\])?:'), 'system_journal',
        'unknown'
    ),
    attributes = mapConcat(
        attributes,
        map(
            'hostname', extract(payload, '^<[0-9]{1,3}>\\s*<([^>]+)>'),
            'call_context', extract(payload, '\\[(C[A-Za-z0-9_-]+)\\]')
        )
    )
WHERE parser_version != 'smg-3.410-v5'
SETTINGS mutations_sync = 1;
