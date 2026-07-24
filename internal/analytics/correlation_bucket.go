package analytics

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

type DirtyCorrelationBucket struct {
	DeviceID uuid.UUID
	Revision uint64
	Bucket   time.Time
	Attempts uint16
}

func (c *Client) EnqueueDirtySyslogBuckets(
	ctx context.Context, events []SyslogEvent,
) error {
	type key struct {
		device   uuid.UUID
		revision uint64
		day      string
	}
	dirty := make(map[key]time.Time)
	for _, event := range events {
		if event.Category != "radius" {
			continue
		}
		occurredAt := event.ReceivedAt
		if event.EventTime != nil {
			occurredAt = *event.EventTime
		}
		revision := event.TimezoneRevision
		if revision == 0 {
			revision = 1
		}
		day := occurredAt.UTC().Truncate(24 * time.Hour)
		dirty[key{event.DeviceID, revision, day.Format("2006-01-02")}] = day
		if occurredAt.UTC().Sub(day) < 10*time.Minute {
			previous := day.Add(-24 * time.Hour)
			dirty[key{event.DeviceID, revision, previous.Format("2006-01-02")}] = previous
		}
		if day.Add(24*time.Hour).Sub(occurredAt.UTC()) <= 10*time.Minute {
			next := day.Add(24 * time.Hour)
			dirty[key{event.DeviceID, revision, next.Format("2006-01-02")}] = next
		}
	}
	if len(dirty) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.correlation_dirty_buckets
		(device_id,timezone_revision,bucket,status,attempts,error,updated_at)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for item, day := range dirty {
		if err := batch.Append(
			item.device, item.revision, day, "pending", uint16(0), "", now,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) EnqueueDirtyCDRBuckets(
	ctx context.Context, records []CDRRecord,
) error {
	events := make([]SyslogEvent, 0, len(records))
	for _, record := range records {
		at := record.IngestedAt
		if record.SetupTime != nil {
			at = *record.SetupTime
		}
		events = append(events, SyslogEvent{
			DeviceID: record.DeviceID, ReceivedAt: at, EventTime: &at,
			Category: "radius", TimezoneRevision: record.TimezoneRevision,
		})
	}
	return c.EnqueueDirtySyslogBuckets(ctx, events)
}

func (c *Client) ListPendingCorrelationBuckets(
	ctx context.Context, limit uint64,
) ([]DirtyCorrelationBucket, error) {
	rows, err := c.Conn.Query(ctx, `SELECT device_id,timezone_revision,bucket,attempts
		FROM collector.correlation_dirty_buckets FINAL
		WHERE status='pending' AND updated_at<=now64(6)-INTERVAL 2 SECOND
		  AND (device_id,timezone_revision) IN
			(SELECT device_id,revision FROM collector.device_derived_revisions FINAL
			 WHERE status='active')
		ORDER BY bucket DESC,updated_at LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]DirtyCorrelationBucket, 0, limit)
	for rows.Next() {
		var item DirtyCorrelationBucket
		if err := rows.Scan(&item.DeviceID, &item.Revision, &item.Bucket, &item.Attempts); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) ReconcileDirtyBucket(
	ctx context.Context, bucket DirtyCorrelationBucket,
) error {
	started := time.Now()
	transactions, err := c.loadBucketTransactions(ctx, bucket)
	if err != nil {
		return c.failDirtyBucket(ctx, bucket, err)
	}
	cdrs, err := c.loadBucketCDRs(ctx, bucket)
	if err != nil {
		return c.failDirtyBucket(ctx, bucket, err)
	}
	assignments := correlateBucket(transactions, cdrs)
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.call_assignments
		(device_id,timezone_revision,transaction_id,updated_at,cdr_record_id,state,
		 method,confidence,time_delta_ms,matched_fields,reason,tombstone)`)
	if err != nil {
		return c.failDirtyBucket(ctx, bucket, err)
	}
	now := time.Now().UTC()
	var exact, composite, ambiguous, orphan uint64
	for transactionID, assignment := range assignments {
		var recordID *uuid.UUID
		if assignment.cdr.ID != uuid.Nil {
			id := assignment.cdr.ID
			recordID = &id
		}
		state := assignment.method
		switch {
		case assignment.ambiguous:
			state = "ambiguous"
			ambiguous++
		case assignment.method == "":
			state = "orphan"
			orphan++
		case strings.HasPrefix(assignment.method, "exact_"):
			state = "exact"
			exact++
		default:
			state = "composite"
			composite++
		}
		fields := strings.Split(assignment.evidence["matched_fields"], ",")
		if len(fields) == 1 && fields[0] == "" {
			fields = nil
		}
		if err := batch.Append(
			bucket.DeviceID, bucket.Revision, transactionID, now, recordID, state,
			assignment.method, assignment.confidence, assignment.timeDeltaMS,
			fields, assignment.reason, uint8(0),
		); err != nil {
			return c.failDirtyBucket(ctx, bucket, err)
		}
	}
	if err := batch.Send(); err != nil {
		return c.failDirtyBucket(ctx, bucket, err)
	}
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.correlation_bucket_runs
		(device_id,timezone_revision,bucket,ran_at,total,exact,composite,ambiguous,orphan,duration_ms)
		VALUES(?,?,?,now64(6),?,?,?,?,?,?)`,
		bucket.DeviceID, bucket.Revision, bucket.Bucket, uint64(len(assignments)),
		exact, composite, ambiguous, orphan, uint64(time.Since(started).Milliseconds()),
	); err != nil {
		return c.failDirtyBucket(ctx, bucket, err)
	}
	var latestStatus string
	var latestUpdatedAt time.Time
	if err := c.Conn.QueryRow(ctx, `SELECT status,updated_at
		FROM collector.correlation_dirty_buckets FINAL
		WHERE device_id=? AND timezone_revision=? AND bucket=? LIMIT 1`,
		bucket.DeviceID, bucket.Revision, bucket.Bucket).
		Scan(&latestStatus, &latestUpdatedAt); err != nil {
		return c.failDirtyBucket(ctx, bucket, err)
	}
	if latestStatus == "pending" && latestUpdatedAt.After(started.UTC()) {
		return nil
	}
	return c.Conn.Exec(ctx, `INSERT INTO collector.correlation_dirty_buckets
		(device_id,timezone_revision,bucket,status,attempts,error,updated_at)
		VALUES(?,?,?,'done',?,'',now64(6))`,
		bucket.DeviceID, bucket.Revision, bucket.Bucket, bucket.Attempts+1)
}

func (c *Client) failDirtyBucket(
	ctx context.Context, bucket DirtyCorrelationBucket, cause error,
) error {
	_ = c.Conn.Exec(ctx, `INSERT INTO collector.correlation_dirty_buckets
		(device_id,timezone_revision,bucket,status,attempts,error,updated_at)
		VALUES(?,?,?,'pending',?,?,now64(6))`,
		bucket.DeviceID, bucket.Revision, bucket.Bucket, bucket.Attempts+1, cause.Error())
	return cause
}

func (c *Client) loadBucketTransactions(
	ctx context.Context, bucket DirtyCorrelationBucket,
) ([]correlationTransaction, error) {
	from := bucket.Bucket.UTC().Add(-10 * time.Minute)
	to := bucket.Bucket.UTC().Add(24*time.Hour + 10*time.Minute)
	rows, err := c.Conn.Query(ctx, `SELECT
		transaction_id,argMax(first_event_at,updated_at),argMax(last_event_at,updated_at),
		argMax(acct_session_id_normalized,updated_at),argMax(call_context,updated_at),
		argMax(calling_station_id,updated_at),argMax(called_station_id,updated_at),
		argMax(src_number_in,updated_at),argMax(dst_number_in,updated_at),
		argMax(src_number_out,updated_at),argMax(dst_number_out,updated_at),
		argMax(in_trunkgroup_label,updated_at),argMax(out_trunkgroup_label,updated_at),
		argMax(attributes,updated_at),argMax(raw_event_ids,updated_at)
		FROM collector.antifraud_lifecycles
		WHERE device_id=? AND timezone_revision=? AND first_event_at>=? AND first_event_at<?
		  AND is_antifraud=1
		GROUP BY transaction_id`,
		bucket.DeviceID, bucket.Revision, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]correlationTransaction, 0)
	for rows.Next() {
		var item correlationTransaction
		if err := rows.Scan(
			&item.ID, &item.FirstEventAt, &item.LastEventAt, &item.Session,
			&item.CallContext, &item.Calling, &item.Called, &item.SrcIn, &item.DstIn,
			&item.SrcOut, &item.DstOut, &item.InRoute, &item.OutRoute,
			&item.Attributes, &item.RawEventIDs,
		); err != nil {
			return nil, err
		}
		item.DeviceID = bucket.DeviceID
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) loadBucketCDRs(
	ctx context.Context, bucket DirtyCorrelationBucket,
) ([]correlationCDR, error) {
	from := bucket.Bucket.UTC().Add(-10 * time.Minute)
	to := bucket.Bucket.UTC().Add(24*time.Hour + 10*time.Minute)
	rows, err := c.Conn.Query(ctx, `SELECT
		c.record_id,t.setup_time,c.radius_session_id_normalized,c.incoming_cgpn,
		c.outgoing_cgpn,c.incoming_cdpn,c.outgoing_cdpn,c.incoming_description,
		c.outgoing_description,c.incoming_sip_call_id,c.outgoing_sip_call_id,c.global_callref
		FROM
		(
			SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time
			FROM collector.cdr_time_facts
			WHERE device_id=? AND timezone_revision=? AND setup_time_utc BETWEEN ? AND ?
			GROUP BY record_id
		) AS t
		INNER JOIN collector.cdr_records AS c ON c.record_id=t.record_id AND c.device_id=?
		WHERE t.setup_time IS NOT NULL`,
		bucket.DeviceID, bucket.Revision, from, to, bucket.DeviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]correlationCDR, 0)
	for rows.Next() {
		var item correlationCDR
		if err := rows.Scan(
			&item.ID, &item.SetupTime, &item.Session, &item.IncomingCgPN,
			&item.OutgoingCgPN, &item.IncomingCdPN, &item.OutgoingCdPN,
			&item.IncomingRoute, &item.OutgoingRoute, &item.IncomingCallID,
			&item.OutgoingCallID, &item.GlobalCallref,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func correlateBucket(
	transactions []correlationTransaction, cdrs []correlationCDR,
) map[uuid.UUID]correlationEdge {
	result := make(map[uuid.UUID]correlationEdge, len(transactions))
	sessionIndex := make(map[string][]correlationCDR)
	callIDIndex := make(map[string][]correlationCDR)
	gcrIndex := make(map[string][]correlationCDR)
	numberIndex := make(map[string]map[uuid.UUID]correlationCDR)
	for _, record := range cdrs {
		if record.Session != "" {
			sessionIndex[record.Session] = append(sessionIndex[record.Session], record)
		}
		for _, value := range []string{record.IncomingCallID, record.OutgoingCallID} {
			if value != "" {
				callIDIndex[value] = append(callIDIndex[value], record)
			}
		}
		if record.GlobalCallref != "" {
			gcrIndex[record.GlobalCallref] = append(gcrIndex[record.GlobalCallref], record)
		}
		for number := range normalizedPhoneSet(
			record.IncomingCgPN, record.OutgoingCgPN, record.IncomingCdPN, record.OutgoingCdPN,
		) {
			if numberIndex[number] == nil {
				numberIndex[number] = make(map[uuid.UUID]correlationCDR)
			}
			numberIndex[number][record.ID] = record
		}
	}
	ordered := append([]correlationTransaction(nil), transactions...)
	sort.Slice(ordered, func(i, j int) bool {
		if !ordered[i].FirstEventAt.Equal(ordered[j].FirstEventAt) {
			return ordered[i].FirstEventAt.Before(ordered[j].FirstEventAt)
		}
		return ordered[i].ID.String() < ordered[j].ID.String()
	})
	for _, transaction := range ordered {
		candidates := append([]correlationCDR(nil), sessionIndex[transaction.Session]...)
		if transaction.Session != "" && len(candidates) != 0 {
			sort.Slice(candidates, func(i, j int) bool {
				return abs64(candidates[i].SetupTime.Sub(transaction.FirstEventAt).Milliseconds()) <
					abs64(candidates[j].SetupTime.Sub(transaction.FirstEventAt).Milliseconds())
			})
			record := candidates[0]
			result[transaction.ID] = correlationEdge{
				transaction: transaction, cdr: record, method: "exact_acct_session",
				confidence:  1,
				timeDeltaMS: record.SetupTime.Sub(transaction.FirstEventAt).Milliseconds(),
				evidence: map[string]string{
					"matched_fields":  "acct_session_id",
					"acct_session_id": transaction.Session,
				},
			}
			continue
		}
		protocolCandidates := make(map[uuid.UUID]correlationCDR)
		for _, callID := range []string{
			transaction.Attributes["incoming_sip_call_id"],
			transaction.Attributes["outgoing_sip_call_id"],
			transaction.Attributes["h323_call_id"],
		} {
			for _, record := range callIDIndex[callID] {
				protocolCandidates[record.ID] = record
			}
		}
		for _, record := range gcrIndex[transaction.Attributes["global_callref"]] {
			protocolCandidates[record.ID] = record
		}
		protocolEdges := make([]correlationEdge, 0, len(protocolCandidates))
		for _, record := range protocolCandidates {
			if edge, ok := exactProtocolCorrelationEdge(transaction, record); ok {
				protocolEdges = append(protocolEdges, edge)
			}
		}
		if len(protocolEdges) != 0 {
			sort.Slice(protocolEdges, func(i, j int) bool {
				return abs64(protocolEdges[i].timeDeltaMS) < abs64(protocolEdges[j].timeDeltaMS)
			})
			best := protocolEdges[0]
			result[transaction.ID] = best
			continue
		}
		group := make(map[uuid.UUID]correlationCDR)
		for number := range normalizedPhoneSet(
			transaction.Calling, transaction.Called, transaction.SrcIn,
			transaction.DstIn, transaction.SrcOut, transaction.DstOut,
		) {
			for id, record := range numberIndex[number] {
				group[id] = record
			}
		}
		edges := make([]correlationEdge, 0, len(group))
		for _, record := range group {
			if edge, ok := compositeCorrelationEdge(transaction, record); ok {
				edges = append(edges, edge)
			}
		}
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].confidence != edges[j].confidence {
				return edges[i].confidence > edges[j].confidence
			}
			if abs64(edges[i].timeDeltaMS) != abs64(edges[j].timeDeltaMS) {
				return abs64(edges[i].timeDeltaMS) < abs64(edges[j].timeDeltaMS)
			}
			return edges[i].cdr.ID.String() < edges[j].cdr.ID.String()
		})
		if len(edges) == 0 {
			result[transaction.ID] = correlationEdge{
				transaction: transaction, reason: "no CDR candidate in normalized signature group",
			}
			continue
		}
		best := edges[0]
		if len(edges) > 1 && best.confidence-edges[1].confidence < 0.05 &&
			abs64(abs64(best.timeDeltaMS)-abs64(edges[1].timeDeltaMS)) < 1000 {
			best.ambiguous = true
			best.reason = "multiple CDR candidates have equivalent evidence"
			result[transaction.ID] = best
			continue
		}
		result[transaction.ID] = best
	}
	return result
}
