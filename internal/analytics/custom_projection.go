package analytics

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"collector/internal/customprojection"
	"collector/internal/customradius"
	"collector/internal/redact"
	"collector/internal/workload"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

func (c *Client) DiscoverSyslogBuckets(
	ctx context.Context, deviceID uuid.UUID, cursorTime time.Time, cursorID uuid.UUID, limit int,
) (customprojection.Discovery, error) {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return customprojection.Discovery{}, err
	}
	defer release()
	if limit <= 0 || limit > 10_000 {
		limit = 128
	}
	// No FINAL: event_id is unique per insert, and ORDER BY matches the table key.
	// FINAL over multi-million syslog_messages starves the shared ClickHouse pool.
	rows, err := c.Conn.Query(ctx, `SELECT DISTINCT received_at,event_id
		FROM collector.syslog_messages
		WHERE device_id=? AND (received_at>? OR (received_at=? AND event_id>?))
		ORDER BY received_at,event_id LIMIT ?`,
		deviceID, cursorTime, cursorTime, cursorID, limit+1)
	if err != nil {
		return customprojection.Discovery{}, err
	}
	defer rows.Close()
	type point struct {
		at time.Time
		id uuid.UUID
	}
	points := make([]point, 0, limit+1)
	for rows.Next() {
		var item point
		if err := rows.Scan(&item.at, &item.id); err != nil {
			return customprojection.Discovery{}, err
		}
		points = append(points, item)
	}
	if err := rows.Err(); err != nil {
		return customprojection.Discovery{}, err
	}
	discovery := customprojection.Discovery{HasMore: len(points) > limit}
	if discovery.HasMore {
		points = points[:limit]
	}
	unique := make(map[time.Time]struct{})
	for _, item := range points {
		unique[item.at.UTC().Truncate(time.Hour)] = struct{}{}
		discovery.NextTime, discovery.NextEventID = item.at, item.id
		discovery.WatermarkTime, discovery.WatermarkID = item.at, item.id
	}
	for bucket := range unique {
		discovery.Buckets = append(discovery.Buckets, bucket)
	}
	sort.Slice(discovery.Buckets, func(i, j int) bool {
		return discovery.Buckets[i].Before(discovery.Buckets[j])
	})
	return discovery, nil
}

func (c *Client) LoadCustomRadiusEvents(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time, limit int,
) ([]customradius.RawEvent, error) {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return nil, err
	}
	defer release()
	if limit <= 0 || limit > 100_000 {
		limit = 20_000
	}
	// Include RADIUS headers and Custom attribute-dump lines. Eltex often logs
	// Acct-Session-Id / Eltex-AVPair on a separate line without the word RADIUS;
	// excluding those dumps leaves packets without session keys.
	rows, err := c.Conn.Query(ctx, `SELECT DISTINCT event_id,device_id,received_at,toString(source_ip),
		source_port,transport,payload FROM collector.syslog_messages
		WHERE device_id=? AND received_at>=? AND received_at<?
		  AND (
			positionCaseInsensitiveUTF8(payload,'RADIUS')>0
			OR positionCaseInsensitiveUTF8(payload,'Antifraud')>0
			OR positionCaseInsensitiveUTF8(payload,'Access-')>0
			OR positionCaseInsensitiveUTF8(payload,'Accounting-')>0
			OR positionCaseInsensitiveUTF8(payload,'Accs-')>0
			OR positionCaseInsensitiveUTF8(payload,'Proc Reply')>0
			OR positionCaseInsensitiveUTF8(payload,'Acct-Session-Id')>0
			OR positionCaseInsensitiveUTF8(payload,'Eltex-AVPair')>0
			OR positionCaseInsensitiveUTF8(payload,'Cisco-AVPair')>0
			OR positionCaseInsensitiveUTF8(payload,'xpgk-request-type')>0
			OR positionCaseInsensitiveUTF8(payload,'h323-conf-id')>0
		  )
		ORDER BY received_at,event_id LIMIT ?`, deviceID, from, to, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]customradius.RawEvent, 0)
	for rows.Next() {
		var event customradius.RawEvent
		if err := rows.Scan(
			&event.EventID, &event.DeviceID, &event.ReceivedAt, &event.SourceIP,
			&event.SourcePort, &event.Transport, &event.Payload,
		); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) > limit {
		return nil, fmt.Errorf("custom projection bucket exceeds %d events", limit)
	}
	return events, nil
}

func (c *Client) LoadCustomRadiusSessionEvents(
	ctx context.Context, deviceID uuid.UUID, identities []string, from, to time.Time,
	_ time.Duration, limit int,
) ([]customradius.RawEvent, error) {
	if len(identities) == 0 {
		return nil, nil
	}
	if limit <= 0 || limit > 100_000 {
		limit = 20_000
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return nil, err
	}
	defer release()
	// Indexed session-event lookup only. Full-payload substring scans over an
	// hour of Syslog starve ClickHouse and block ingest.
	rows, err := c.Conn.Query(ctx, `SELECT DISTINCT message.event_id,message.device_id,
		message.received_at,toString(message.source_ip),message.source_port,
		message.transport,message.payload
		FROM collector.custom_radius_session_events_current AS session
		INNER JOIN collector.syslog_messages AS message
			ON message.device_id=session.device_id AND message.event_id=session.event_id
		WHERE session.device_id=? AND session.identity_value IN ?
		  AND message.received_at>=? AND message.received_at<?
		ORDER BY message.received_at,message.event_id LIMIT ?`,
		deviceID, identities, from, to, limit+1)
	if err != nil {
		return nil, err
	}
	return scanCustomRadiusEvents(rows, limit)
}

func scanCustomRadiusEvents(rows driver.Rows, limit int) ([]customradius.RawEvent, error) {
	defer rows.Close()
	events := make([]customradius.RawEvent, 0)
	for rows.Next() {
		var event customradius.RawEvent
		if err := rows.Scan(
			&event.EventID, &event.DeviceID, &event.ReceivedAt, &event.SourceIP,
			&event.SourcePort, &event.Transport, &event.Payload,
		); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) > limit {
		return nil, fmt.Errorf("custom session scan exceeds %d events", limit)
	}
	return events, nil
}

func mergeAnalyticsEvents(
	left, right []customradius.RawEvent, limit int,
) ([]customradius.RawEvent, error) {
	unique := make(map[uuid.UUID]customradius.RawEvent)
	for _, events := range [][]customradius.RawEvent{left, right} {
		for _, event := range events {
			unique[event.EventID] = event
		}
	}
	if len(unique) > limit {
		return nil, fmt.Errorf("custom session expansion exceeds %d events", limit)
	}
	events := make([]customradius.RawEvent, 0, len(unique))
	for _, event := range unique {
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].ReceivedAt.Equal(events[j].ReceivedAt) {
			return events[i].EventID.String() < events[j].EventID.String()
		}
		return events[i].ReceivedAt.Before(events[j].ReceivedAt)
	})
	return events, nil
}

func (c *Client) WriteCustomProjectionSnapshot(
	ctx context.Context, snapshot customprojection.Snapshot,
) error {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	if err := c.writeCustomPackets(ctx, snapshot); err != nil {
		return err
	}
	return c.writeCustomCalls(ctx, snapshot)
}

func (c *Client) writeCustomPackets(ctx context.Context, snapshot customprojection.Snapshot) error {
	type packetRow struct {
		args []any
	}
	type memberRow struct {
		args []any
	}
	type exchangeRow struct {
		args []any
	}
	type sessionRow struct {
		args []any
	}
	packets := make([]packetRow, 0)
	members := make([]memberRow, 0)
	exchanges := make([]exchangeRow, 0)
	sessions := make([]sessionRow, 0)
	for _, packet := range snapshot.Result.Packets {
		if packet.FirstSeenAt.Before(snapshot.BucketStart) ||
			!packet.FirstSeenAt.Before(snapshot.BucketStart.Add(time.Hour)) {
			continue
		}
		attributes, _ := json.Marshal(redactAttributes(packet.Attributes))
		provenance, _ := json.Marshal(packet.Provenance)
		warnings, _ := json.Marshal(packet.Warnings)
		orphanReason, ambiguityReason := "", ""
		if packet.Status == customradius.PacketOrphan {
			orphanReason = firstExplanationCode(packet.Explanations)
		}
		if packet.Status == customradius.PacketAmbiguous {
			ambiguityReason = firstExplanationCode(packet.Explanations)
		}
		packets = append(packets, packetRow{args: []any{
			snapshot.DeviceID, snapshot.BucketStart, snapshot.ID, snapshot.PolicyRevision,
			snapshot.ProjectionSeq, packet.ID, packet.FirstSeenAt, packet.LastSeenAt,
			customContractKey(packet.CallKey), packet.CallKey.AcctSessionID, packet.CallKey.H323ConfID,
			string(packet.Family), packet.RadiusType, string(packet.Direction), string(packet.Phase),
			string(packet.Decision), string(packet.Confidence), string(packet.Status),
			boolByte(packet.IsAntifraud), chUUIDPtr(packet.RequestID), chUUIDPtr(packet.ResponseID),
			string(attributes), string(provenance), explanationCodes(packet.Explanations),
			string(warnings), orphanReason, ambiguityReason, uint8(0),
		}})
		for index, member := range packet.Provenance {
			members = append(members, memberRow{args: []any{
				snapshot.DeviceID, snapshot.BucketStart, snapshot.ID, snapshot.PolicyRevision,
				snapshot.ProjectionSeq, packet.ID, uint16(index), member.EventID, member.ReceivedAt,
				net.ParseIP(member.SourceIP), member.SourcePort, uint8(0),
			}})
			for _, identity := range []struct {
				kind  string
				value string
			}{
				{kind: "acct_session_id", value: packet.CallKey.AcctSessionID},
				{kind: "h323_conf_id", value: packet.CallKey.H323ConfID},
			} {
				if identity.value == "" {
					continue
				}
				sessions = append(sessions, sessionRow{args: []any{
					snapshot.DeviceID, snapshot.BucketStart, snapshot.ID,
					snapshot.PolicyRevision, snapshot.ProjectionSeq, identity.kind, identity.value,
					member.EventID, member.ReceivedAt, uint8(0),
				}})
			}
		}
		if packet.Direction == customradius.DirectionRequest {
			exchanges = append(exchanges, exchangeRow{args: []any{
				snapshot.DeviceID, snapshot.BucketStart, snapshot.ID, snapshot.PolicyRevision,
				snapshot.ProjectionSeq, packet.ID, customContractKey(packet.CallKey),
				packet.CallKey.AcctSessionID, packet.CallKey.H323ConfID, packet.ID,
				chUUIDPtr(packet.ResponseID), packet.AttemptIDs, string(packet.Status),
				string(packet.Decision), explanationCodes(packet.Explanations), packet.FirstSeenAt,
				uint8(0),
			}})
		}
	}
	// One PrepareBatch at a time: each open batch holds a pooled connection.
	if err := c.withBatch(ctx, `INSERT INTO collector.custom_radius_packets
		(device_id,bucket_start,snapshot_id,policy_revision,projection_seq,packet_id,
		first_seen_at,last_seen_at,contract_key,acct_session_id,h323_conf_id,family,radius_type,
		direction,phase,decision,confidence,status,is_antifraud,request_id,response_id,
		ordered_attributes_json,provenance_json,explanation_codes,warnings_json,
		orphan_reason,ambiguity_reason,deleted)`, func(batch driver.Batch) error {
		for _, row := range packets {
			if err := batch.Append(row.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := c.withBatch(ctx, `INSERT INTO collector.custom_radius_packet_members
		(device_id,bucket_start,snapshot_id,policy_revision,projection_seq,packet_id,member_order,
		event_id,received_at,source_ip,source_port,deleted)`, func(batch driver.Batch) error {
		for _, row := range members {
			if err := batch.Append(row.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := c.withBatch(ctx, `INSERT INTO collector.custom_radius_session_events
		(device_id,bucket_start,snapshot_id,policy_revision,projection_seq,identity_kind,
		identity_value,event_id,received_at,deleted)`, func(batch driver.Batch) error {
		for _, row := range sessions {
			if err := batch.Append(row.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return c.withBatch(ctx, `INSERT INTO collector.custom_radius_exchanges
		(device_id,bucket_start,snapshot_id,policy_revision,projection_seq,exchange_id,contract_key,
		acct_session_id,h323_conf_id,request_id,response_id,attempt_ids,status,decision,
		explanation_codes,occurred_at,deleted)`, func(batch driver.Batch) error {
		for _, row := range exchanges {
			if err := batch.Append(row.args...); err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *Client) writeCustomCalls(ctx context.Context, snapshot customprojection.Snapshot) error {
	type callRow struct {
		args []any
	}
	type linkRow struct {
		args []any
	}
	calls := make([]callRow, 0)
	links := make([]linkRow, 0)
	for _, call := range snapshot.Result.Calls {
		if len(call.Packets) == 0 {
			continue
		}
		first, last := call.Packets[0].FirstSeenAt, call.Packets[0].LastSeenAt
		for _, packet := range call.Packets[1:] {
			if packet.FirstSeenAt.Before(first) {
				first = packet.FirstSeenAt
			}
			if packet.LastSeenAt.After(last) {
				last = packet.LastSeenAt
			}
		}
		if first.Before(snapshot.BucketStart) || !first.Before(snapshot.BucketStart.Add(time.Hour)) {
			continue
		}
		attributes, _ := json.Marshal(redactAttributes(call.Attributes))
		unmatched, _ := json.Marshal(call.Unmatched)
		calls = append(calls, callRow{args: []any{
			snapshot.DeviceID, snapshot.BucketStart, snapshot.ID, snapshot.PolicyRevision,
			snapshot.ProjectionSeq, call.ID, customContractKey(call.Key),
			call.Key.AcctSessionID, call.Key.H323ConfID, call.Participants.Calling,
			call.Participants.Called, string(call.Status), "awaiting_cdr",
			chTimePtr(call.Accounting.StartTime), chTimePtr(call.Accounting.StopTime),
			call.Accounting.SessionDuration, string(attributes),
			string(unmatched), call.Orphans, explanationCodes(call.Explanations), first, last, uint8(0),
		}})
		for index, packet := range call.Packets {
			links = append(links, linkRow{args: []any{
				snapshot.DeviceID, snapshot.BucketStart, snapshot.ID, snapshot.PolicyRevision,
				snapshot.ProjectionSeq, call.ID, packet.ID, uint16(index), packet.FirstSeenAt, uint8(0),
			}})
		}
	}
	if err := c.withBatch(ctx, `INSERT INTO collector.custom_antifraud_calls
		(device_id,bucket_start,snapshot_id,policy_revision,projection_seq,call_id,contract_key,
		acct_session_id,h323_conf_id,calling,called,status,coverage_state,accounting_start,accounting_stop,
		session_duration_seconds,ordered_attributes_json,unmatched_provenance_json,
		orphan_packet_ids,explanation_codes,first_seen_at,last_seen_at,deleted)`, func(batch driver.Batch) error {
		for _, row := range calls {
			if err := batch.Append(row.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return c.withBatch(ctx, `INSERT INTO collector.custom_antifraud_call_packets
		(device_id,bucket_start,snapshot_id,policy_revision,projection_seq,call_id,packet_id,
		packet_order,occurred_at,deleted)`, func(batch driver.Batch) error {
		for _, row := range links {
			if err := batch.Append(row.args...); err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *Client) ActivateCustomProjectionSnapshot(
	ctx context.Context, snapshot customprojection.Snapshot,
) error {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	var previous *uuid.UUID
	err = c.Conn.QueryRow(ctx, `SELECT nullIf(
			argMaxIf(snapshot_id,projection_seq,marker='active'),
			toUUID('00000000-0000-0000-0000-000000000000'))
		FROM collector.custom_projection_state
		WHERE device_id=? AND bucket_start=?`, snapshot.DeviceID, snapshot.BucketStart).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	rowCount := uint64(len(snapshot.Result.Packets) + len(snapshot.Result.Calls))
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.custom_projection_state
		(device_id,bucket_start,policy_revision,projection_seq,snapshot_id,previous_snapshot_id,
		marker,watermark_received_at,watermark_event_id,row_count,activated_at,deleted)
		VALUES(?,?,?,?,?,?,'active',?,?,?,?,0)`,
		snapshot.DeviceID, snapshot.BucketStart, snapshot.PolicyRevision, snapshot.ProjectionSeq,
		snapshot.ID, chUUIDPtr(previous), chTime(snapshot.WatermarkTime),
		chUUID(snapshot.WatermarkID), rowCount, time.Now().UTC()); err != nil {
		return err
	}
	if len(snapshot.Result.Calls) != 0 {
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.cdr_reconciliation_dirty_buckets
			(device_id,bucket_start,policy_revision,projection_seq,reason,enqueued_at,deleted)
			VALUES(?,?,?,?,?,now64(6),0)`,
			snapshot.DeviceID, snapshot.BucketStart, snapshot.PolicyRevision,
			snapshot.ProjectionSeq, "custom_call_snapshot"); err != nil {
			return err
		}
	}
	if previous == nil || *previous == uuid.Nil || *previous == snapshot.ID {
		return nil
	}
	return c.tombstoneCustomSnapshot(ctx, snapshot, *previous)
}

func (c *Client) tombstoneCustomSnapshot(
	ctx context.Context, snapshot customprojection.Snapshot, previous uuid.UUID,
) error {
	queries := []string{
		`INSERT INTO collector.custom_radius_packets SELECT * REPLACE (? AS projection_seq, toUInt8(1) AS deleted)
		 FROM collector.custom_radius_packets WHERE device_id=? AND bucket_start=? AND snapshot_id=?`,
		`INSERT INTO collector.custom_radius_packet_members SELECT * REPLACE (? AS projection_seq, toUInt8(1) AS deleted)
		 FROM collector.custom_radius_packet_members WHERE device_id=? AND bucket_start=? AND snapshot_id=?`,
		`INSERT INTO collector.custom_radius_exchanges SELECT * REPLACE (? AS projection_seq, toUInt8(1) AS deleted)
		 FROM collector.custom_radius_exchanges WHERE device_id=? AND bucket_start=? AND snapshot_id=?`,
		`INSERT INTO collector.custom_antifraud_calls SELECT * REPLACE (? AS projection_seq, toUInt8(1) AS deleted)
		 FROM collector.custom_antifraud_calls WHERE device_id=? AND bucket_start=? AND snapshot_id=?`,
		`INSERT INTO collector.custom_antifraud_call_packets SELECT * REPLACE (? AS projection_seq, toUInt8(1) AS deleted)
		 FROM collector.custom_antifraud_call_packets WHERE device_id=? AND bucket_start=? AND snapshot_id=?`,
		`INSERT INTO collector.custom_radius_session_events SELECT * REPLACE (? AS projection_seq, toUInt8(1) AS deleted)
		 FROM collector.custom_radius_session_events WHERE device_id=? AND bucket_start=? AND snapshot_id=?`,
	}
	for _, query := range queries {
		if err := c.Conn.Exec(
			ctx, query, snapshot.ProjectionSeq, snapshot.DeviceID, snapshot.BucketStart, previous,
		); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) WriteCustomProjectionDisabled(
	ctx context.Context, job customprojection.Job,
) error {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.custom_projection_state
		(device_id,bucket_start,policy_revision,projection_seq,snapshot_id,marker,row_count,
		activated_at,deleted)
		SELECT device_id,bucket_start,?, ?,toUUID('00000000-0000-0000-0000-000000000000'),
			'disabled',0,now64(6),0
		FROM collector.custom_projection_state
		WHERE device_id=? GROUP BY device_id,bucket_start`,
		job.PolicyRevision, job.ProjectionSeq, job.DeviceID); err != nil {
		return err
	}
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.cdr_antifraud_coverage
		(device_id,event_month,cdr_id,policy_revision,reconciliation_version,projection_seq,
		state,expected_at,grace_expires_at,missing_terminal_at,retry_until,matched_call_id,
		method,reason,delta_ms,matched_evidence_json,ambiguous,ambiguity_reason,updated_at,deleted)
		SELECT device_id,event_month,cdr_id,?,reconciliation_version,?,
			'not_applicable',expected_at,grace_expires_at,missing_terminal_at,retry_until,NULL,
			'none','device_disabled',NULL,'{}',0,'',now64(6),0
		FROM collector.cdr_antifraud_coverage_current WHERE device_id=?`,
		job.PolicyRevision, job.ProjectionSeq, job.DeviceID); err != nil {
		return err
	}
	return c.Conn.Exec(ctx, `INSERT INTO collector.cdr_reconciliation_dirty_buckets
		(device_id,bucket_start,policy_revision,projection_seq,reason,enqueued_at,deleted)
		SELECT device_id,bucket_start,?,?,'device_disabled',now64(6),1
		FROM collector.cdr_reconciliation_dirty_buckets
		WHERE device_id=? GROUP BY device_id,bucket_start`,
		job.PolicyRevision, job.ProjectionSeq, job.DeviceID)
}

func (c *Client) RollbackCustomProjection(
	ctx context.Context, deviceID uuid.UUID, bucket time.Time, projectionSeq uint64,
) error {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	return c.Conn.Exec(ctx, `INSERT INTO collector.custom_projection_state
		(device_id,bucket_start,policy_revision,projection_seq,snapshot_id,previous_snapshot_id,
		marker,row_count,activated_at,deleted)
		SELECT device_id,bucket_start,policy_revision,?,assumeNotNull(previous_snapshot_id),snapshot_id,
			'active',row_count,now64(6),0
		FROM collector.custom_projection_state
		WHERE device_id=? AND bucket_start=? AND previous_snapshot_id IS NOT NULL
		ORDER BY projection_seq DESC LIMIT 1`, projectionSeq, deviceID, bucket)
}

type CustomProjectionMetrics struct {
	ProjectionLagSeconds  int64  `json:"projectionLagSeconds"`
	Calls                 uint64 `json:"calls"`
	Orphans               uint64 `json:"orphans"`
	Ambiguous             uint64 `json:"ambiguous"`
	CoverageMatched       uint64 `json:"coverageMatched"`
	CoverageExpected      uint64 `json:"coverageExpected"`
	CoverageLate          uint64 `json:"coverageLate"`
	CoverageMissing       uint64 `json:"coverageMissing"`
	CoverageNotApplicable uint64 `json:"coverageNotApplicable"`
	CoverageAmbiguous     uint64 `json:"coverageAmbiguous"`
}

func (c *Client) CustomProjectionMetrics(
	ctx context.Context, deviceID uuid.UUID,
) (CustomProjectionMetrics, error) {
	ctx, release, err := c.queryContext(ctx, workload.Diagnostics)
	if err != nil {
		return CustomProjectionMetrics{}, err
	}
	defer release()
	var result CustomProjectionMetrics
	if err := c.Conn.QueryRow(ctx, `SELECT
		greatest(0,dateDiff('second',ifNull(max(activated_at),now64(6)),now64(6))),
		(SELECT count() FROM collector.custom_antifraud_calls_current WHERE device_id=?),
		(SELECT count() FROM collector.custom_radius_packets_current
			WHERE device_id=? AND orphan_reason!=''),
		(SELECT count() FROM collector.custom_radius_packets_current
			WHERE device_id=? AND ambiguity_reason!='')
		FROM collector.custom_projection_state WHERE device_id=?`,
		deviceID, deviceID, deviceID, deviceID,
	).Scan(&result.ProjectionLagSeconds, &result.Calls, &result.Orphans, &result.Ambiguous); err != nil {
		return result, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT
		countIf(state='matched'),countIf(state='expected'),countIf(state='late'),
		countIf(state='missing'),countIf(state='not_applicable'),countIf(ambiguous=1)
		FROM collector.cdr_antifraud_coverage_current WHERE device_id=?`, deviceID).Scan(
		&result.CoverageMatched, &result.CoverageExpected, &result.CoverageLate,
		&result.CoverageMissing, &result.CoverageNotApplicable, &result.CoverageAmbiguous,
	); err != nil {
		return result, err
	}
	return result, nil
}

type CustomDiagnostic struct {
	At         time.Time `json:"at"`
	EntityID   uuid.UUID `json:"entityId"`
	EntityType string    `json:"entityType"`
	State      string    `json:"state"`
	Reason     string    `json:"reason"`
}

func (c *Client) ListCustomDiagnostics(
	ctx context.Context, deviceID uuid.UUID, limit uint64,
) ([]CustomDiagnostic, error) {
	ctx, release, err := c.queryContext(ctx, workload.Diagnostics)
	if err != nil {
		return nil, err
	}
	defer release()
	if limit == 0 || limit > 500 {
		limit = 100
	}
	rows, err := c.Conn.Query(ctx, `SELECT updated_at,cdr_id,'cdr',state,
		if(ambiguity_reason='',reason,ambiguity_reason)
		FROM collector.cdr_antifraud_coverage_current
		WHERE device_id=? AND (state IN ('expected','late','missing') OR ambiguous=1)
		ORDER BY updated_at DESC,cdr_id DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CustomDiagnostic, 0, limit)
	for rows.Next() {
		var item CustomDiagnostic
		if err := rows.Scan(
			&item.At, &item.EntityID, &item.EntityType, &item.State, &item.Reason,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func customContractKey(key customradius.CallKey) string {
	if key.AcctSessionID != "" {
		return "session:" + key.AcctSessionID
	}
	if key.H323ConfID != "" {
		return "h323:" + key.H323ConfID
	}
	return ""
}

func explanationCodes(items []customradius.Explanation) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		result = append(result, item.Code)
	}
	return result
}

func firstExplanationCode(items []customradius.Explanation) string {
	if len(items) == 0 {
		return ""
	}
	return items[0].Code
}

func boolByte(value bool) uint8 {
	if value {
		return 1
	}
	return 0
}

func normalizeIdentity(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), ""))
}

func redactAttributes(attributes []customradius.Attribute) []customradius.Attribute {
	result := append([]customradius.Attribute(nil), attributes...)
	for index := range result {
		if redact.SecretName(result[index].Name) || redact.SecretName(result[index].DisplayName) {
			result[index].Value = ""
			result[index].RawValue = ""
			result[index].Redacted = true
		}
	}
	return result
}
