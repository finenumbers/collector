CREATE OR REPLACE VIEW collector.current_antifraud_calls AS
SELECT
    device_id,
    timezone_revision,
    parser_version,
    call_id,
    max(source.updated_at) AS updated_at,
    min(first_event_at) AS first_event_at,
    max(last_event_at) AS last_event_at,
    argMax(source.identity_kind, tuple(
        multiIf(source.identity_kind='acct_session_id',3,
            source.identity_kind='h323_conf_id',2,1),
        source.updated_at)) AS identity_kind,
    argMax(source.identity_value, tuple(
        multiIf(source.identity_kind='acct_session_id',3,
            source.identity_kind='h323_conf_id',2,1),
        source.updated_at)) AS identity_value,
    argMaxIf(acct_session_id, source.updated_at, acct_session_id!='') AS acct_session_id,
    argMaxIf(acct_session_id_normalized, source.updated_at,
        acct_session_id_normalized!='') AS acct_session_id_normalized,
    argMaxIf(h323_conf_id, source.updated_at, h323_conf_id!='') AS h323_conf_id,
    arrayDistinct(arrayFlatten(groupArray(call_contexts))) AS call_contexts,
    arrayDistinct(arrayFlatten(groupArray(raw_event_ids))) AS raw_event_ids
FROM collector.antifraud_calls AS source
GROUP BY device_id, timezone_revision, parser_version, call_id;
