package analytics

import (
	"context"
	"crypto/sha1"
	"sort"
	"strings"
	"time"

	"collector/internal/reconciliation"
	"collector/internal/workload"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

func (c *Client) DiscoverCDRBuckets(
	ctx context.Context, deviceID uuid.UUID, cursorTime time.Time, cursorID uuid.UUID, limit int,
) ([]time.Time, time.Time, uuid.UUID, bool, error) {
	const maxDiscover = 5000
	if limit <= 0 || limit > maxDiscover {
		limit = 256
	}
	rows, err := c.Conn.Query(ctx, `SELECT record_id,
		coalesce(setup_time,connect_time,disconnect_time,ingested_at)
		FROM collector.cdr_records FINAL
		WHERE device_id=? AND (
			coalesce(setup_time,connect_time,disconnect_time,ingested_at)>?
			OR (coalesce(setup_time,connect_time,disconnect_time,ingested_at)=? AND record_id>?))
		ORDER BY coalesce(setup_time,connect_time,disconnect_time,ingested_at),record_id
		LIMIT ?`, deviceID, cursorTime, cursorTime, cursorID, limit+1)
	if err != nil {
		return nil, time.Time{}, uuid.Nil, false, err
	}
	defer rows.Close()
	type item struct {
		id uuid.UUID
		at time.Time
	}
	items := make([]item, 0, maxDiscover+1)
	for rows.Next() {
		var value item
		if err := rows.Scan(&value.id, &value.at); err != nil {
			return nil, time.Time{}, uuid.Nil, false, err
		}
		items = append(items, value)
	}
	if err := rows.Err(); err != nil {
		return nil, time.Time{}, uuid.Nil, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	unique := make(map[time.Time]struct{})
	var nextTime time.Time
	var nextID uuid.UUID
	for _, value := range items {
		unique[value.at.UTC().Truncate(time.Hour)] = struct{}{}
		nextTime, nextID = value.at, value.id
	}
	buckets := make([]time.Time, 0, len(unique))
	for bucket := range unique {
		buckets = append(buckets, bucket)
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Before(buckets[j]) })
	return buckets, nextTime, nextID, hasMore, nil
}

func (c *Client) LoadReconciliationEvidence(
	ctx context.Context, bucket reconciliation.Bucket, horizon time.Duration,
) ([]reconciliation.CDR, []reconciliation.Call, error) {
	ctx, release, err := c.queryContext(ctx, workload.CustomReconcile)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	from, to := bucket.Start.Add(-horizon), bucket.Start.Add(time.Hour+horizon)
	cdrRows, err := c.Conn.Query(ctx, `SELECT record_id,device_id,
		coalesce(setup_time,connect_time,disconnect_time,ingested_at),ingested_at,
		radius_session_id_normalized,raw_fields,incoming_cgpn,incoming_cdpn
		FROM collector.cdr_records
		WHERE device_id=? AND coalesce(setup_time,connect_time,disconnect_time,ingested_at)>=?
		  AND coalesce(setup_time,connect_time,disconnect_time,ingested_at)<?
		  AND record_id NOT IN (
			SELECT cdr_id FROM collector.cdr_antifraud_assignments_current
			WHERE device_id=? AND policy_revision=?
		  )
		ORDER BY coalesce(setup_time,connect_time,disconnect_time,ingested_at),record_id
		LIMIT 50000`,
		bucket.DeviceID, from, to, bucket.DeviceID, bucket.PolicyRevision)
	if err != nil {
		return nil, nil, err
	}
	cdrs := make([]reconciliation.CDR, 0)
	for cdrRows.Next() {
		var item reconciliation.CDR
		var raw map[string]string
		if err := cdrRows.Scan(
			&item.ID, &item.DeviceID, &item.EventTime, &item.IngestedAt,
			&item.AcctSessionID, &raw, &item.Calling, &item.Called,
		); err != nil {
			cdrRows.Close()
			return nil, nil, err
		}
		item.Enabled, item.PolicyRevision = true, bucket.PolicyRevision
		item.H323FieldValues = realH323Values(raw)
		cdrs = append(cdrs, item)
	}
	if err := cdrRows.Close(); err != nil {
		return nil, nil, err
	}
	callRows, err := c.Conn.Query(ctx, `SELECT call_id,device_id,first_seen_at,
		acct_session_id,h323_conf_id,calling,called,policy_revision
		FROM collector.custom_antifraud_calls_current
		WHERE device_id=? AND policy_revision=? AND first_seen_at>=? AND first_seen_at<?
		  AND call_id NOT IN (
			SELECT call_id FROM collector.cdr_antifraud_assignments_current
			WHERE device_id=? AND policy_revision=?
		  )
		ORDER BY first_seen_at,call_id LIMIT 50000`,
		bucket.DeviceID, bucket.PolicyRevision, from, to,
		bucket.DeviceID, bucket.PolicyRevision)
	if err != nil {
		return nil, nil, err
	}
	defer callRows.Close()
	calls := make([]reconciliation.Call, 0)
	for callRows.Next() {
		var item reconciliation.Call
		if err := callRows.Scan(
			&item.ID, &item.DeviceID, &item.EventTime, &item.AcctSessionID,
			&item.H323ConfID, &item.Calling, &item.Called, &item.PolicyRevision,
		); err != nil {
			return nil, nil, err
		}
		calls = append(calls, item)
	}
	return cdrs, calls, callRows.Err()
}

func (c *Client) WriteReconciliationResult(
	ctx context.Context, bucket reconciliation.Bucket, result reconciliation.Result,
	config reconciliation.Config,
) error {
	ctx, release, err := c.queryContext(ctx, workload.CustomReconcile)
	if err != nil {
		return err
	}
	defer release()
	_ = config
	now := time.Now().UTC()
	seq := uint64(now.UnixNano())
	if err := c.withBatch(ctx, `INSERT INTO collector.cdr_antifraud_coverage
		(device_id,event_month,cdr_id,policy_revision,reconciliation_version,projection_seq,
		state,expected_at,grace_expires_at,missing_terminal_at,retry_until,matched_call_id,
		method,reason,delta_ms,matched_evidence_json,ambiguous,ambiguity_reason,updated_at,deleted)`,
		func(batch driver.Batch) error {
			for _, coverage := range result.Coverage {
				var callID *uuid.UUID
				method, delta, evidence := "none", (*int64)(nil), "{}"
				if coverage.Assignment != nil {
					callID = &coverage.Assignment.CallID
					method = coverage.Assignment.Method
					value := coverage.Assignment.Delta.Milliseconds()
					delta = &value
					evidence = encodeEvidence(coverage.Assignment.MatchedEvidence)
				}
				if err := batch.Append(
					bucket.DeviceID, monthDate(coverage.ExpectedAt), coverage.CDRID,
					bucket.PolicyRevision, reconciliation.Version, seq, string(coverage.State),
					coverage.ExpectedAt, coverage.GraceExpiresAt, coverage.MissingAt,
					coverage.RetryUntil, callID, method, coverage.Reason, delta, evidence,
					boolByte(coverage.Ambiguous), coverage.AmbiguityReason, now, uint8(0),
				); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
		return err
	}
	if err := c.withBatch(ctx, `INSERT INTO collector.cdr_antifraud_assignments
		(device_id,event_month,assignment_id,cdr_id,call_id,policy_revision,
		reconciliation_version,projection_seq,method,reason,delta_ms,matched_evidence_json,
		assigned_at,ambiguous,ambiguity_reason,deleted)`, func(batch driver.Batch) error {
		for _, assignment := range result.Assignments {
			delta := assignment.Delta.Milliseconds()
			assignmentID := uuid.NewHash(
				sha1.New(), uuid.NameSpaceOID,
				[]byte(assignment.CDRID.String()+"\x00"+assignment.CallID.String()), 5,
			)
			if err := batch.Append(
				bucket.DeviceID, monthDate(now), assignmentID, assignment.CDRID, assignment.CallID,
				bucket.PolicyRevision, assignment.Version, seq, assignment.Method, assignment.Reason,
				&delta, encodeEvidence(assignment.MatchedEvidence), now, uint8(0), "", uint8(0),
			); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return c.Conn.Exec(ctx, `INSERT INTO collector.cdr_reconciliation_dirty_buckets
		(device_id,bucket_start,policy_revision,projection_seq,reason,enqueued_at,deleted)
		VALUES(?,?,?,?,?,now64(6),1)`,
		bucket.DeviceID, bucket.Start, bucket.PolicyRevision, seq, "processed")
}

func realH323Values(raw map[string]string) []string {
	values := make([]string, 0)
	for key, value := range raw {
		normalizedKey := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		if strings.Contains(normalizedKey, "h323") &&
			(strings.Contains(normalizedKey, "conf") || strings.Contains(normalizedKey, "conference")) &&
			strings.TrimSpace(value) != "" {
			values = append(values, value)
		}
	}
	return values
}
