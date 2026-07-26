package analytics

import (
	"context"
	"time"

	"github.com/google/uuid"
)

func (c *Client) hasOperationProjection(
	ctx context.Context, deviceID uuid.UUID, revision uint64,
) (bool, error) {
	var status string
	err := c.Conn.QueryRow(ctx, `SELECT argMax(status,updated_at)
		FROM collector.parser_projection_state
		WHERE device_id=? AND timezone_revision=? AND parser_version=?`,
		deviceID, revision, SyslogParserVersion).Scan(&status)
	return status == "active", err
}

func (c *Client) hasProjectedOperation(
	ctx context.Context, deviceID uuid.UUID, revision uint64, operationID uuid.UUID,
) (bool, error) {
	var count uint64
	err := c.Conn.QueryRow(ctx, `SELECT count()
		FROM collector.current_antifraud_operations
		WHERE device_id=? AND timezone_revision=? AND parser_version=? AND operation_id=?
		  AND EXISTS
		  (
			SELECT 1 FROM collector.parser_projection_state
			WHERE device_id=? AND timezone_revision=? AND parser_version=?
			GROUP BY device_id,timezone_revision,parser_version
			HAVING argMax(status,updated_at)='active'
		  )`,
		deviceID, revision, SyslogParserVersion, operationID,
		deviceID, revision, SyslogParserVersion).Scan(&count)
	return count > 0, err
}

// ActivateParserProjection atomically exposes a completely replayed parser projection.
// Live v16 rows can be written while replay is running, but readers remain on the
// legacy projection until this marker is inserted after the replay watermark is reached.
func (c *Client) ActivateParserProjection(
	ctx context.Context, deviceID uuid.UUID, revision uint64, parserVersion string,
) error {
	return c.Conn.Exec(ctx, `INSERT INTO collector.parser_projection_state
		(device_id,timezone_revision,parser_version,status,updated_at)
		VALUES(?,?,?,'active',now64(6))`,
		deviceID, revision, parserVersion)
}

func (c *Client) listOperationAntifraudPage(
	ctx context.Context,
	deviceID uuid.UUID,
	revision uint64,
	search string,
	limit uint64,
	cursor *AntifraudCursor,
	timeRange *TimeRange,
) (AntifraudPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	timezone, err := c.deviceRevisionTimezone(ctx, deviceID, revision)
	if err != nil {
		return AntifraudPage{}, err
	}
	query := `WITH links AS
		(
			SELECT operation_id,latest.1 AS cdr_record_id,latest.2 AS state,
				latest.3 AS method,latest.4 AS time_delta_ms,latest.5 AS reason
			FROM
			(
				SELECT operation_id,argMax(
					tuple(cdr_record_id,state,method,time_delta_ms,reason),
					tuple(updated_at,state,method,reason)
				) AS latest
				FROM collector.antifraud_operation_cdr_links
				WHERE device_id=? AND timezone_revision=? AND parser_version=?
				GROUP BY operation_id
			)
		),
		cdr_times AS
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.cdr_time_facts
			WHERE device_id=? AND timezone_revision=?
			GROUP BY record_id
		)
		SELECT o.operation_id,o.first_event_at,o.last_event_at,o.call_context,
			if(c.acct_session_id='',o.acct_session_id_normalized,c.acct_session_id),
			o.operation_type,ifNull(req.packet_code,''),ifNull(resp.packet_code,''),
			o.decision,o.terminal_reason,
			ifNull(req.attributes['server_address'],''),ifNull(req.retry,0),
			if(req.packet_id=toUUID('00000000-0000-0000-0000-000000000000')
				OR resp.packet_id=toUUID('00000000-0000-0000-0000-000000000000'),
				CAST(NULL,'Nullable(UInt32)'),
				toNullable(toUInt32(greatest(
					dateDiff('millisecond',req.occurred_at,resp.occurred_at),0)))),
			ifNull(req.attributes['calling_station_id'],''),
			ifNull(req.attributes['called_station_id'],''),
			ifNull(req.attributes['xpgk_src_number_in'],''),
			ifNull(req.attributes['xpgk_dst_number_in'],''),
			ifNull(req.attributes['xpgk_src_number_out'],''),
			ifNull(req.attributes['xpgk_dst_number_out'],''),
			ifNull(req.attributes['in_trunkgroup_label'],''),
			ifNull(req.attributes['out_trunkgroup_label'],''),
			if(o.operation_type='accounting',o.terminal_state,''),
			o.q850_cause,
			if(o.terminal_state IN (
				'outstanding','incomplete_response','ambiguous','ambiguous_response'
			),
				'incomplete','complete'),
			mapConcat(ifNull(req.attributes,map()),ifNull(resp.attributes,map()),
				map('terminal_state',o.terminal_state,'terminal_reason',o.terminal_reason)),
			if(l.cdr_record_id IS NULL OR l.state!='linked',[],
				[assumeNotNull(l.cdr_record_id)]),
			toUInt64(if(l.cdr_record_id IS NULL OR l.state!='linked',0,1)),
			ct.setup_time,ifNull(l.method,''),
			toFloat32(if(l.state='linked',1,0)),ifNull(l.time_delta_ms,0),
			ifNull(l.reason,''),ifNull(d.radius_session_id,''),
			if(l.state='linked','exact',ifNull(l.state,'orphan')),[],?
		FROM collector.current_antifraud_operations AS o
		LEFT JOIN collector.current_antifraud_packets AS req
		  ON req.device_id=o.device_id AND req.timezone_revision=o.timezone_revision
		 AND req.parser_version=o.parser_version AND req.packet_id=o.request_packet_id
		LEFT JOIN collector.current_antifraud_packets AS resp
		  ON resp.device_id=o.device_id AND resp.timezone_revision=o.timezone_revision
		 AND resp.parser_version=o.parser_version AND resp.packet_id=o.response_packet_id
		LEFT JOIN collector.current_antifraud_calls AS c
		  ON c.device_id=o.device_id AND c.timezone_revision=o.timezone_revision
		 AND c.parser_version=o.parser_version AND c.call_id=o.call_id
		LEFT JOIN links AS l ON l.operation_id=o.operation_id
		LEFT JOIN cdr_times AS ct ON ct.record_id=l.cdr_record_id
		LEFT JOIN collector.cdr_records AS d
		  ON d.device_id=o.device_id AND d.record_id=l.cdr_record_id
		WHERE o.device_id=? AND o.timezone_revision=? AND o.parser_version=?`
	args := []any{
		deviceID, revision, SyslogParserVersion,
		deviceID, revision, timezone,
		deviceID, revision, SyslogParserVersion,
	}
	if timeRange != nil {
		query += ` AND o.last_event_at>=? AND o.last_event_at<?`
		args = append(args, timeRange.From, timeRange.To)
	}
	if search != "" {
		query += ` AND (positionCaseInsensitive(o.operation_type,?)>0
			OR positionCaseInsensitive(o.call_context,?)>0
			OR positionCaseInsensitive(o.acct_session_id_normalized,?)>0
			OR positionCaseInsensitive(toString(req.attributes),?)>0
			OR positionCaseInsensitive(toString(resp.attributes),?)>0)`
		for range 5 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (o.last_event_at<? OR
			(o.last_event_at=? AND o.operation_id<?))`
		args = append(args, cursor.LastEventAt, cursor.LastEventAt, cursor.TransactionID)
	}
	query += ` ORDER BY o.last_event_at DESC,o.operation_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return AntifraudPage{}, err
	}
	defer rows.Close()
	items := make([]AntifraudRow, 0, limit+1)
	for rows.Next() {
		var item AntifraudRow
		if err := rows.Scan(
			&item.TransactionID, &item.FirstEventAt, &item.LastEventAt,
			&item.CallContext, &item.AcctSessionID, &item.RequestType,
			&item.RequestCode, &item.ResponseCode, &item.Decision,
			&item.DecisionReason, &item.ServerAddress, &item.Retries,
			&item.LatencyMS, &item.CallingStationID, &item.CalledStationID,
			&item.SrcNumberIn, &item.DstNumberIn, &item.SrcNumberOut,
			&item.DstNumberOut, &item.InTrunkgroupLabel,
			&item.OutTrunkgroupLabel, &item.AccountingStatus, &item.Q850Cause,
			&item.Completeness, &item.Attributes, &item.LinkedRecordIDs,
			&item.LegCount, &item.CDRSetupTime, &item.CorrelationMethod,
			&item.CorrelationConfidence, &item.CorrelationTimeDeltaMS,
			&item.AmbiguityReason, &item.CDRSessionID, &item.CorrelationState,
			&item.MatchedFields, &item.SourceTimezone,
		); err != nil {
			return AntifraudPage{}, err
		}
		item.Attributes = sanitizePublicAttributes(item.Attributes)
		item.FirstEventLocal = localRFC3339(&item.FirstEventAt, timezone)
		item.LastEventLocal = localRFC3339(&item.LastEventAt, timezone)
		item.CDRSetupLocal = localRFC3339(item.CDRSetupTime, timezone)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return AntifraudPage{}, err
	}
	hasMore := uint64(len(items)) > limit
	if hasMore {
		items = items[:limit]
	}
	return AntifraudPage{Items: items, HasMore: hasMore}, nil
}

func (c *Client) operationAntifraudTimeline(
	ctx context.Context, deviceID uuid.UUID, revision uint64, operationID uuid.UUID,
) ([]TimelineRow, error) {
	rows, err := c.Conn.Query(ctx, `WITH operation AS
		(
			SELECT raw_event_ids FROM collector.current_antifraud_operations
			WHERE device_id=? AND timezone_revision=? AND parser_version=?
			  AND operation_id=?
		)
		SELECT f.event_id,argMax(f.received_at,f.interpreted_at),
			argMax(f.event_time_utc,f.interpreted_at),argMax(f.category,f.interpreted_at),
			argMax(f.component,f.interpreted_at),argMax(f.message,f.interpreted_at),
			any(r.payload),argMax(f.parse_status,f.interpreted_at),
			argMax(f.attributes,f.interpreted_at),argMax(f.source_timezone,f.interpreted_at)
		FROM collector.syslog_facts AS f
		ANY INNER JOIN collector.raw_syslog AS r
		  ON r.device_id=f.device_id AND r.event_id=f.event_id
		WHERE f.device_id=? AND f.timezone_revision=?
		  AND f.event_id IN (SELECT arrayJoin(raw_event_ids) FROM operation)
		GROUP BY f.event_id ORDER BY argMax(f.received_at,f.interpreted_at)`,
		deviceID, revision, SyslogParserVersion, operationID, deviceID, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TimelineRow, 0)
	for rows.Next() {
		var item TimelineRow
		if err := rows.Scan(
			&item.EventID, &item.ReceivedAt, &item.EventTime, &item.Category,
			&item.Component, &item.Message, &item.RawPayload, &item.Status,
			&item.Attributes, &item.SourceTimezone,
		); err != nil {
			return nil, err
		}
		item.Method = "antifraud_operation"
		item.Confidence = 1
		sanitizeEventPresentation(&item.EventRow)
		result = append(result, item)
	}
	return result, rows.Err()
}
