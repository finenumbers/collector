package analytics

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

func (c *Client) deviceRevisionTimezone(
	ctx context.Context, deviceID uuid.UUID, revision uint64,
) (string, error) {
	var timezone string
	err := c.Conn.QueryRow(ctx, `SELECT timezone
		FROM collector.device_derived_revisions FINAL
		WHERE device_id=? AND revision=? LIMIT 1`, deviceID, revision).Scan(&timezone)
	return timezone, err
}

func localRFC3339(value *time.Time, timezone string) string {
	if value == nil {
		return ""
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return ""
	}
	return value.In(location).Format(time.RFC3339Nano)
}

func (c *Client) ActiveDeviceRevision(ctx context.Context, deviceID uuid.UUID) (uint64, error) {
	var revision uint64
	err := c.Conn.QueryRow(ctx, `SELECT max(revision)
		FROM collector.device_derived_revisions FINAL
		WHERE device_id=? AND status='active'`, deviceID).Scan(&revision)
	return revision, err
}

func (c *Client) listCurrentEventsPage(
	ctx context.Context,
	deviceID uuid.UUID,
	revision uint64,
	category string,
	search string,
	limit uint64,
	cursor *EventCursor,
) (EventPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	timezone, err := c.deviceRevisionTimezone(ctx, deviceID, revision)
	if err != nil {
		return EventPage{}, err
	}
	query := `WITH page AS
		(
			SELECT event_id,received_at,payload,event_time,category,component,message,
				parse_status,attributes,source_timezone
			FROM collector.raw_syslog
			WHERE device_id=?`
	args := []any{deviceID}
	if category != "" && category != "all" {
		query += ` AND category=?`
		args = append(args, category)
	}
	if search != "" {
		query += ` AND positionCaseInsensitive(payload,?)>0`
		args = append(args, search)
	}
	if cursor != nil {
		query += ` AND (received_at<? OR (received_at=? AND event_id<?))`
		args = append(args, cursor.ReceivedAt, cursor.ReceivedAt, cursor.EventID)
	}
	query += ` ORDER BY received_at DESC,event_id DESC LIMIT 1 BY event_id LIMIT ?
		),
		facts AS
		(
			SELECT event_id,
				argMax(event_time_utc,interpreted_at) AS event_time,
				argMax(category,interpreted_at) AS category,
				argMax(component,interpreted_at) AS component,
				argMax(message,interpreted_at) AS message,
				argMax(parse_status,interpreted_at) AS parse_status,
				argMax(attributes,interpreted_at) AS attributes,
				argMax(source_timezone,interpreted_at) AS source_timezone
			FROM collector.syslog_facts
			WHERE device_id=? AND timezone_revision=?
			  AND event_id IN (SELECT event_id FROM page)
			GROUP BY event_id
		)
		SELECT p.event_id,p.received_at,
			if(f.event_id=toUUID('00000000-0000-0000-0000-000000000000'),p.event_time,f.event_time),
			if(f.event_id=toUUID('00000000-0000-0000-0000-000000000000'),p.category,f.category),
			if(f.event_id=toUUID('00000000-0000-0000-0000-000000000000'),p.component,f.component),
			if(f.event_id=toUUID('00000000-0000-0000-0000-000000000000'),p.message,f.message),
			p.payload,
			if(f.event_id=toUUID('00000000-0000-0000-0000-000000000000'),p.parse_status,f.parse_status),
			if(f.event_id=toUUID('00000000-0000-0000-0000-000000000000'),p.attributes,f.attributes),
			if(f.event_id=toUUID('00000000-0000-0000-0000-000000000000'),p.source_timezone,f.source_timezone)
		FROM page AS p
		LEFT JOIN facts AS f ON f.event_id=p.event_id
		ORDER BY p.received_at DESC,p.event_id DESC`
	args = append(args, limit+1, deviceID, revision)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	result := make([]EventRow, 0, limit+1)
	for rows.Next() {
		var row EventRow
		if err := rows.Scan(
			&row.EventID, &row.ReceivedAt, &row.EventTime, &row.Category,
			&row.Component, &row.Message, &row.RawPayload, &row.Status,
			&row.Attributes, &row.SourceTimezone,
		); err != nil {
			return EventPage{}, err
		}
		row.EventTimeLocal = localRFC3339(row.EventTime, timezone)
		row.ReceivedAtLocal = localRFC3339(&row.ReceivedAt, timezone)
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return EventPage{}, err
	}
	hasMore := uint64(len(result)) > limit
	if hasMore {
		result = result[:limit]
	}
	return EventPage{Items: result, HasMore: hasMore}, nil
}

func (c *Client) listFallbackEventsPage(
	ctx context.Context,
	deviceID uuid.UUID,
	category string,
	search string,
	limit uint64,
	cursor *EventCursor,
) (EventPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	query := `SELECT event_id,received_at,event_time,category,component,message,
		payload,parse_status,attributes,source_timezone
		FROM collector.raw_syslog WHERE device_id=?`
	args := []any{deviceID}
	if category != "" && category != "all" {
		query += ` AND category=?`
		args = append(args, category)
	}
	if search != "" {
		query += ` AND positionCaseInsensitive(payload,?)>0`
		args = append(args, search)
	}
	if cursor != nil {
		query += ` AND (received_at<? OR (received_at=? AND event_id<?))`
		args = append(args, cursor.ReceivedAt, cursor.ReceivedAt, cursor.EventID)
	}
	query += ` ORDER BY received_at DESC,event_id DESC LIMIT 1 BY event_id LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	result := make([]EventRow, 0, limit+1)
	for rows.Next() {
		var row EventRow
		if err := rows.Scan(
			&row.EventID, &row.ReceivedAt, &row.EventTime, &row.Category,
			&row.Component, &row.Message, &row.RawPayload, &row.Status,
			&row.Attributes, &row.SourceTimezone,
		); err != nil {
			return EventPage{}, err
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return EventPage{}, err
	}
	hasMore := uint64(len(result)) > limit
	if hasMore {
		result = result[:limit]
	}
	return EventPage{Items: result, HasMore: hasMore}, nil
}

func (c *Client) listCurrentCallsPage(
	ctx context.Context,
	deviceID uuid.UUID,
	revision uint64,
	search string,
	limit uint64,
	cursor *CallCursor,
) (CallPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	timezone, err := c.deviceRevisionTimezone(ctx, deviceID, revision)
	if err != nil {
		return CallPage{}, err
	}
	query := `WITH source AS
		(
			SELECT *,
				coalesce(
					parseDateTime64BestEffortOrNull(
						coalesce(nullIf(raw_fields['setup_time'],''),nullIf(raw_fields['setup'],'')),
						6,?),
					ingested_at) AS source_sort_time
			FROM collector.cdr_records
			WHERE device_id=?
		),
		page AS
		(
			SELECT record_id AS page_record_id,source_sort_time AS sort_time
			FROM source AS c
			WHERE 1`
	args := []any{timezone, deviceID}
	if search != "" {
		query += ` AND (positionCaseInsensitive(c.incoming_cgpn,?)>0
			OR positionCaseInsensitive(c.outgoing_cgpn,?)>0
			OR positionCaseInsensitive(c.incoming_cdpn,?)>0
			OR positionCaseInsensitive(c.outgoing_cdpn,?)>0
			OR positionCaseInsensitive(c.radius_session_id,?)>0
			OR positionCaseInsensitive(c.unique_tag,?)>0
			OR positionCaseInsensitive(c.incoming_description,?)>0
			OR positionCaseInsensitive(c.outgoing_description,?)>0)`
		for range 8 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (sort_time<? OR (sort_time=? AND c.record_id<?))`
		args = append(args, cursor.SortTime, cursor.SortTime, cursor.RecordID)
	}
	query += ` ORDER BY sort_time DESC,c.record_id DESC LIMIT 1 BY c.record_id LIMIT ?
		),
		times AS
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.cdr_time_facts
			WHERE device_id=? AND timezone_revision=?
			  AND record_id IN (SELECT page_record_id FROM page)
			GROUP BY record_id
		)
		SELECT c.record_id,t.setup_time,c.duration_ms,c.release_cause,c.release_info,
			c.incoming_cgpn,c.outgoing_cgpn,c.incoming_cdpn,c.outgoing_cdpn,
			c.incoming_description,c.outgoing_description,c.radius_session_id,c.unique_tag,
			p.sort_time
		FROM page AS p
		LEFT JOIN times AS t ON t.record_id=p.page_record_id
		ANY INNER JOIN collector.cdr_records AS c
			ON c.device_id=? AND c.record_id=p.page_record_id
		ORDER BY p.sort_time DESC,c.record_id DESC`
	args = append(args, limit+1, deviceID, revision, deviceID)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return CallPage{}, err
	}
	defer rows.Close()
	result := make([]CallRow, 0, limit+1)
	for rows.Next() {
		var row CallRow
		if err := rows.Scan(
			&row.RecordID, &row.SetupTime, &row.DurationMS, &row.ReleaseCause,
			&row.ReleaseInfo, &row.IncomingCgPN, &row.OutgoingCgPN,
			&row.IncomingCdPN, &row.OutgoingCdPN, &row.IncomingDescription,
			&row.OutgoingDescription, &row.RadiusSessionID, &row.UniqueTag,
			&row.SortTime,
		); err != nil {
			return CallPage{}, err
		}
		row.SourceTimezone = timezone
		row.SetupTimeLocal = localRFC3339(row.SetupTime, timezone)
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return CallPage{}, err
	}
	hasMore := uint64(len(result)) > limit
	if hasMore {
		result = result[:limit]
	}
	return CallPage{Items: result, HasMore: hasMore}, nil
}

func compactMatchedFields(fields []string) string {
	filtered := fields[:0]
	for _, field := range fields {
		if value := strings.TrimSpace(field); value != "" {
			filtered = append(filtered, value)
		}
	}
	return strings.Join(filtered, ",")
}

func (c *Client) listCurrentAntifraudPage(
	ctx context.Context,
	deviceID uuid.UUID,
	revision uint64,
	search string,
	limit uint64,
	cursor *AntifraudCursor,
) (AntifraudPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sourceTimezone, err := c.deviceRevisionTimezone(ctx, deviceID, revision)
	if err != nil {
		return AntifraudPage{}, err
	}
	query := `WITH page AS
		(
			SELECT transaction_id,first_event_at,last_event_at,call_context,
				acct_session_id,request_type,request_code,response_code,decision,
				decision_reason,server_address,retries,latency_ms,calling_station_id,
				called_station_id,src_number_in,dst_number_in,src_number_out,dst_number_out,
				in_trunkgroup_label,out_trunkgroup_label,accounting_status,q850_cause,
				completeness,attributes
			FROM collector.antifraud_lifecycles FINAL
			WHERE device_id=? AND timezone_revision=? AND is_antifraud=1`
	args := []any{deviceID, revision}
	if search != "" {
		query += ` AND (positionCaseInsensitive(acct_session_id,?)>0
			OR positionCaseInsensitive(calling_station_id,?)>0
			OR positionCaseInsensitive(called_station_id,?)>0
			OR positionCaseInsensitive(toString(attributes),?)>0)`
		for range 4 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (last_event_at<? OR (last_event_at=? AND transaction_id<?))`
		args = append(args, cursor.LastEventAt, cursor.LastEventAt, cursor.TransactionID)
	}
	query += ` ORDER BY last_event_at DESC,transaction_id DESC LIMIT ?
		),
		assignments AS
		(
			SELECT transaction_id,
				argMax(cdr_record_id,updated_at) AS cdr_record_id,
				argMax(state,updated_at) AS state,
				argMax(method,updated_at) AS method,
				argMax(confidence,updated_at) AS confidence,
				argMax(time_delta_ms,updated_at) AS time_delta_ms,
				argMax(matched_fields,updated_at) AS matched_fields,
				argMax(reason,updated_at) AS reason
			FROM collector.call_assignments
			WHERE device_id=? AND timezone_revision=?
			  AND transaction_id IN (SELECT transaction_id FROM page)
			GROUP BY transaction_id
		),
		cdr_times AS
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.cdr_time_facts
			WHERE device_id=? AND timezone_revision=?
			  AND record_id IN (SELECT assumeNotNull(cdr_record_id) FROM assignments
				WHERE cdr_record_id IS NOT NULL AND state IN ('exact','composite'))
			GROUP BY record_id
		)
		SELECT p.transaction_id,p.first_event_at,p.last_event_at,p.call_context,
			p.acct_session_id,p.request_type,p.request_code,p.response_code,p.decision,
			p.decision_reason,p.server_address,p.retries,p.latency_ms,p.calling_station_id,
			p.called_station_id,p.src_number_in,p.dst_number_in,p.src_number_out,p.dst_number_out,
			p.in_trunkgroup_label,p.out_trunkgroup_label,p.accounting_status,p.q850_cause,
			p.completeness,p.attributes,
			if(a.cdr_record_id IS NULL OR a.state NOT IN ('exact','composite'),
				[],[assumeNotNull(a.cdr_record_id)]) AS record_ids,
			toUInt64(if(a.cdr_record_id IS NULL OR a.state NOT IN ('exact','composite'),0,1))
				AS leg_count,ct.setup_time,
			ifNull(a.method,''),ifNull(a.confidence,0),ifNull(a.time_delta_ms,0),
			ifNull(a.reason,''),ifNull(c.radius_session_id,''),ifNull(a.state,'orphan'),
			ifNull(a.matched_fields,[]),?
		FROM page AS p
		LEFT JOIN assignments AS a ON a.transaction_id=p.transaction_id
		LEFT JOIN cdr_times AS ct ON ct.record_id=a.cdr_record_id
		LEFT JOIN collector.cdr_records AS c
			ON c.device_id=? AND c.record_id=a.cdr_record_id
		ORDER BY p.last_event_at DESC,p.transaction_id DESC`
	args = append(args, limit+1, deviceID, revision, deviceID, revision,
		sourceTimezone, deviceID)
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
		item.FirstEventLocal = localRFC3339(&item.FirstEventAt, sourceTimezone)
		item.LastEventLocal = localRFC3339(&item.LastEventAt, sourceTimezone)
		item.CDRSetupLocal = localRFC3339(item.CDRSetupTime, sourceTimezone)
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

func (c *Client) currentCallTimeline(
	ctx context.Context, deviceID uuid.UUID, revision uint64, recordID uuid.UUID,
) ([]TimelineRow, error) {
	rows, err := c.Conn.Query(ctx, `SELECT transaction_id,argMax(method,updated_at)
		FROM collector.call_assignments
		WHERE device_id=? AND timezone_revision=? AND cdr_record_id=?
		  AND tombstone=0 AND state IN ('exact','composite')
		GROUP BY transaction_id`, deviceID, revision, recordID)
	if err != nil {
		return nil, err
	}
	type assignment struct {
		transactionID uuid.UUID
		method        string
	}
	assignments := make([]assignment, 0)
	for rows.Next() {
		var item assignment
		if err := rows.Scan(&item.transactionID, &item.method); err != nil {
			rows.Close()
			return nil, err
		}
		assignments = append(assignments, item)
	}
	rows.Close()
	result := make([]TimelineRow, 0)
	for _, item := range assignments {
		timeline, err := c.currentAntifraudTimeline(
			ctx, deviceID, revision, item.transactionID, item.method,
		)
		if err != nil {
			return nil, err
		}
		result = append(result, timeline...)
	}
	result = deduplicateTimeline(result)
	sortTimeline(result)
	return result, nil
}

func deduplicateTimeline(rows []TimelineRow) []TimelineRow {
	result := make([]TimelineRow, 0, len(rows))
	index := make(map[uuid.UUID]int, len(rows))
	for _, row := range rows {
		if position, ok := index[row.EventID]; ok {
			if row.Confidence > result[position].Confidence {
				result[position].Confidence = row.Confidence
				result[position].Method = row.Method
			}
			continue
		}
		index[row.EventID] = len(result)
		result = append(result, row)
	}
	return result
}

func (c *Client) currentAntifraudTimeline(
	ctx context.Context,
	deviceID uuid.UUID,
	revision uint64,
	transactionID uuid.UUID,
	method string,
) ([]TimelineRow, error) {
	rows, err := c.Conn.Query(ctx, `WITH lifecycle AS
		(
			SELECT argMax(raw_event_ids,updated_at) AS event_ids,
				argMax(call_context,updated_at) AS call_context,
				argMax(first_event_at,updated_at) AS first_event_at,
				argMax(last_event_at,updated_at) AS last_event_at
			FROM collector.antifraud_lifecycles
			WHERE device_id=? AND timezone_revision=? AND transaction_id=?
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
		  AND (f.event_id IN (SELECT arrayJoin(event_ids) FROM lifecycle)
			OR (f.attributes['call_context']=(SELECT call_context FROM lifecycle)
				AND f.event_time_utc BETWEEN
					(SELECT first_event_at-INTERVAL 10 SECOND FROM lifecycle)
					AND (SELECT last_event_at+INTERVAL 10 SECOND FROM lifecycle)))
		GROUP BY f.event_id
		ORDER BY argMax(f.received_at,f.interpreted_at)`,
		deviceID, revision, transactionID, deviceID, revision)
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
		item.Method = method
		item.Confidence = 1
		result = append(result, item)
	}
	return result, rows.Err()
}

func sortTimeline(rows []TimelineRow) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].ReceivedAt.Equal(rows[j].ReceivedAt) {
			return rows[i].ReceivedAt.Before(rows[j].ReceivedAt)
		}
		return rows[i].EventID.String() < rows[j].EventID.String()
	})
}

func (c *Client) currentDiagnostics(
	ctx context.Context, deviceID uuid.UUID, revision uint64,
) (SyslogDiagnostics, error) {
	result := SyslogDiagnostics{
		Breakdown: make([]SyslogBreakdownRow, 0), ActiveRevision: revision,
	}
	rows, err := c.Conn.Query(ctx, `SELECT category,parse_status,count(),max(max_received_at)
		FROM
		(
			SELECT event_id,argMax(category,interpreted_at) AS category,
				argMax(parse_status,interpreted_at) AS parse_status,
				argMax(received_at,interpreted_at) AS max_received_at
			FROM collector.syslog_facts
			WHERE device_id=? AND timezone_revision=?
			  AND received_at>=now()-INTERVAL 24 HOUR
			GROUP BY event_id
		)
		GROUP BY category,parse_status ORDER BY count() DESC`, deviceID, revision)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item SyslogBreakdownRow
		if err := rows.Scan(
			&item.Category, &item.ParseStatus, &item.Count, &item.LastReceivedAt,
		); err != nil {
			rows.Close()
			return result, err
		}
		item.ParserVersion = "shadow-revision"
		result.Breakdown = append(result.Breakdown, item)
	}
	rows.Close()
	migrationRows, err := c.Conn.Query(ctx,
		`SELECT version FROM collector.schema_migrations FINAL ORDER BY version`)
	if err != nil {
		return result, err
	}
	for migrationRows.Next() {
		var version string
		if err := migrationRows.Scan(&version); err != nil {
			migrationRows.Close()
			return result, err
		}
		result.AppliedMigrations = append(result.AppliedMigrations, version)
	}
	migrationRows.Close()
	_ = c.Conn.QueryRow(ctx, `SELECT revision,timezone,status,processed,raw_total,
		cdr_processed,cdr_total
		FROM collector.device_derived_revisions FINAL
		WHERE device_id=? AND status IN ('building','cutover')
		ORDER BY revision DESC LIMIT 1`, deviceID).
		Scan(&result.BuildingRevision, &result.RevisionTimezone, &result.RevisionStatus,
			&result.ReplayProcessed, &result.ReplayTotal, &result.CDRReplayProcessed,
			&result.CDRReplayTotal)
	if result.BuildingRevision == 0 {
		result.RevisionTimezone, err = c.deviceRevisionTimezone(ctx, deviceID, revision)
		if err != nil {
			return result, err
		}
		result.RevisionStatus = "active"
	}
	if err := c.Conn.QueryRow(ctx, `SELECT
		(SELECT countDistinct(event_id) FROM collector.raw_syslog
		 WHERE device_id=? AND received_at>=now()-INTERVAL 24 HOUR),
		(SELECT count() FROM
			(SELECT event_id,argMax(category,interpreted_at) AS category
			 FROM collector.syslog_facts
			 WHERE device_id=? AND timezone_revision=?
			   AND received_at>=now()-INTERVAL 24 HOUR
			 GROUP BY event_id HAVING category!='unknown')),
		toUInt64(greatest(
			(SELECT count() FROM collector.cdr_records WHERE device_id=?)
				- (SELECT countDistinct(record_id) FROM collector.cdr_time_facts
				   WHERE device_id=? AND timezone_revision=?),0)),
		(SELECT countDistinct(event_id) FROM collector.radius_fragments
		 WHERE device_id=? AND timezone_revision=?),
		(SELECT count() FROM
			(SELECT transaction_id FROM collector.antifraud_lifecycles
			 WHERE device_id=? AND timezone_revision=? AND is_antifraud=1
			 GROUP BY transaction_id))`,
		deviceID, deviceID, revision, deviceID, deviceID, revision,
		deviceID, revision, deviceID, revision).
		Scan(&result.RawEvents24h, &result.Classified24h, &result.MissingCDRTimes,
			&result.RadiusRawFragments, &result.LifecycleDerived); err != nil {
		return result, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT
		count(),countIf(state='exact'),countIf(state='composite'),
		countIf(state='ambiguous'),countIf(state='orphan')
		FROM
		(
			SELECT transaction_id,argMax(state,updated_at) AS state
			FROM collector.call_assignments
			WHERE device_id=? AND timezone_revision=?
			GROUP BY transaction_id
		)`, deviceID, revision).
		Scan(&result.CorrelationTotal, &result.CorrelationExact,
			&result.CorrelationComposite, &result.CorrelationAmbiguous,
			&result.CorrelationOrphan); err != nil {
		return result, err
	}
	result.AntifraudOrphan = result.CorrelationOrphan
	if err := c.Conn.QueryRow(ctx, `SELECT
		(SELECT coalesce(max(received_at),toDateTime64(0,6,'UTC'))
		 FROM collector.raw_syslog WHERE device_id=?),
		(SELECT coalesce(max(interpreted_at),toDateTime64(0,6,'UTC'))
		 FROM collector.syslog_facts WHERE device_id=? AND timezone_revision=?),
		(SELECT coalesce(max(updated_at),toDateTime64(0,6,'UTC'))
		 FROM collector.antifraud_lifecycles WHERE device_id=? AND timezone_revision=?),
		(SELECT coalesce(max(updated_at),toDateTime64(0,6,'UTC'))
		 FROM collector.call_assignments WHERE device_id=? AND timezone_revision=?),
		(SELECT count() FROM collector.correlation_dirty_buckets FINAL
		 WHERE device_id=? AND timezone_revision=? AND status='pending'),
		(SELECT coalesce(min(updated_at),toDateTime64(0,6,'UTC'))
		 FROM collector.correlation_dirty_buckets FINAL
		 WHERE device_id=? AND timezone_revision=? AND status='pending')`,
		deviceID, deviceID, revision, deviceID, revision, deviceID, revision,
		deviceID, revision, deviceID, revision).
		Scan(&result.LatestRawAt, &result.LatestFactAt, &result.LatestLifecycleAt,
			&result.LatestAssignmentAt, &result.PendingDirtyBuckets, &result.OldestDirtyAt); err != nil {
		return result, err
	}
	result.ReprocessedCurrent = result.ReplayProcessed
	if result.ReplayTotal > result.ReplayProcessed {
		result.ReprocessRemaining = result.ReplayTotal - result.ReplayProcessed
	}
	return result, nil
}

func (c *Client) currentStats(
	ctx context.Context, deviceID uuid.UUID, revision uint64,
) (DeviceStats, error) {
	var result DeviceStats
	if err := c.Conn.QueryRow(ctx, `SELECT count(),countIf(c.release_cause IS NOT NULL
			AND c.release_cause!=16),ifNull(avg(c.duration_ms),0)
		FROM
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.cdr_time_facts
			WHERE device_id=? AND timezone_revision=?
			GROUP BY record_id HAVING setup_time>=now()-INTERVAL 24 HOUR
		) AS t
		ANY INNER JOIN collector.cdr_records AS c
			ON c.device_id=? AND c.record_id=t.record_id`,
		deviceID, revision, deviceID).
		Scan(&result.Calls24h, &result.FailedCalls24h, &result.AverageTalkMS); err != nil {
		return result, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT countIf(category='alarms'),
		countIf(category='radius'),countIf(category='unknown')
		FROM
		(
			SELECT event_id,argMax(category,interpreted_at) AS category
			FROM collector.syslog_facts
			WHERE device_id=? AND timezone_revision=?
			  AND received_at>=now()-INTERVAL 24 HOUR
			GROUP BY event_id
		)`, deviceID, revision).
		Scan(&result.Alarms24h, &result.Radius24h, &result.Unknown24h); err != nil {
		return result, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT count(),countIf(decision='reject'),
		countIf(completeness!='complete')
		FROM
		(
			SELECT transaction_id,argMax(decision,updated_at) AS decision,
				argMax(completeness,updated_at) AS completeness,
				argMax(last_event_at,updated_at) AS last_event_at
			FROM collector.antifraud_lifecycles
			WHERE device_id=? AND timezone_revision=? AND is_antifraud=1
			GROUP BY transaction_id HAVING last_event_at>=now()-INTERVAL 24 HOUR
		)`, deviceID, revision).
		Scan(&result.Antifraud24h, &result.AntifraudRejected24h,
			&result.AntifraudIncomplete24h); err != nil {
		return result, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT count()
		FROM
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.cdr_time_facts
			WHERE device_id=? AND timezone_revision=?
			GROUP BY record_id HAVING setup_time>=now()-INTERVAL 24 HOUR
		) AS t
		LEFT JOIN
		(
			SELECT assumeNotNull(cdr_record_id) AS record_id
			FROM collector.call_assignments
			WHERE device_id=? AND timezone_revision=?
			GROUP BY transaction_id,cdr_record_id
			HAVING argMax(state,updated_at) IN ('exact','composite')
		) AS a ON a.record_id=t.record_id
		WHERE a.record_id=toUUID('00000000-0000-0000-0000-000000000000')`,
		deviceID, revision, deviceID, revision).Scan(&result.UnlinkedCalls24h); err != nil {
		return result, err
	}
	return result, nil
}
