ALTER TABLE collector.antifraud_calls
    ADD COLUMN IF NOT EXISTS h323_conf_id_normalized String
        DEFAULT lower(replaceRegexpAll(h323_conf_id, '\\s+', '')) AFTER h323_conf_id,
    ADD COLUMN IF NOT EXISTS leg_session_ids Array(String) DEFAULT [] AFTER call_contexts,
    ADD COLUMN IF NOT EXISTS leg_session_ids_normalized Array(String)
        DEFAULT arrayMap(value -> lower(replaceRegexpAll(value, '\\s+', '')), leg_session_ids)
        AFTER leg_session_ids;

ALTER TABLE collector.antifraud_operations
    ADD COLUMN IF NOT EXISTS acct_session_id String DEFAULT '' AFTER call_context;

CREATE OR REPLACE VIEW collector.current_antifraud_operations AS
SELECT
    device_id, timezone_revision, parser_version, operation_id,
    max(source.updated_at) AS updated_at,
    argMax(first_event_at, tuple(source.updated_at, source.operation_id)) AS first_event_at,
    argMax(last_event_at, tuple(source.updated_at, source.operation_id)) AS last_event_at,
    argMax(call_id, tuple(source.updated_at, source.operation_id)) AS call_id,
    argMax(operation_type, tuple(source.updated_at, source.operation_id)) AS operation_type,
    argMax(occurrence, tuple(source.updated_at, source.operation_id)) AS occurrence,
    argMax(call_context, tuple(source.updated_at, source.operation_id)) AS call_context,
    argMax(acct_session_id, tuple(source.updated_at, source.operation_id)) AS acct_session_id,
    argMax(acct_session_id_normalized, tuple(source.updated_at, source.operation_id))
        AS acct_session_id_normalized,
    argMax(request_packet_id, tuple(source.updated_at, source.operation_id)) AS request_packet_id,
    argMax(response_packet_id, tuple(source.updated_at, source.operation_id)) AS response_packet_id,
    argMax(terminal_state, tuple(source.updated_at, source.operation_id)) AS terminal_state,
    argMax(terminal_reason, tuple(source.updated_at, source.operation_id)) AS terminal_reason,
    argMax(decision, tuple(source.updated_at, source.operation_id)) AS decision,
    argMax(q850_cause, tuple(source.updated_at, source.operation_id)) AS q850_cause,
    argMax(raw_event_ids, tuple(source.updated_at, source.operation_id)) AS raw_event_ids
FROM collector.antifraud_operations AS source
GROUP BY device_id, timezone_revision, parser_version, operation_id;

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
        multiIf(source.identity_kind='h323_conf_id',3,
            source.identity_kind='acct_session_id',2,1),
        source.updated_at,
        source.call_id)) AS identity_kind,
    argMax(source.identity_value, tuple(
        multiIf(source.identity_kind='h323_conf_id',3,
            source.identity_kind='acct_session_id',2,1),
        source.updated_at,
        source.call_id)) AS identity_value,
    argMaxIf(acct_session_id, tuple(source.updated_at, source.call_id),
        acct_session_id!='') AS acct_session_id,
    argMaxIf(acct_session_id_normalized, tuple(source.updated_at, source.call_id),
        acct_session_id_normalized!='') AS acct_session_id_normalized,
    argMaxIf(h323_conf_id, tuple(source.updated_at, source.call_id),
        h323_conf_id!='') AS h323_conf_id,
    argMaxIf(h323_conf_id_normalized, tuple(source.updated_at, source.call_id),
        h323_conf_id_normalized!='') AS h323_conf_id_normalized,
    arraySort(arrayDistinct(arrayFlatten(groupArray(call_contexts)))) AS call_contexts,
    arraySort(arrayDistinct(arrayFlatten(groupArray(raw_event_ids)))) AS raw_event_ids,
    arraySort(arrayDistinct(arrayConcat(
        arrayFilter(value -> value!='', groupArray(source.acct_session_id)),
        arrayFlatten(groupArray(source.leg_session_ids))
    ))) AS leg_session_ids,
    arraySort(arrayDistinct(arrayConcat(
        arrayFilter(value -> value!='', groupArray(source.acct_session_id_normalized)),
        arrayFlatten(groupArray(source.leg_session_ids_normalized))
    ))) AS leg_session_ids_normalized
FROM collector.antifraud_calls AS source
GROUP BY device_id, timezone_revision, parser_version, call_id;
