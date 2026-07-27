package analytics

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"collector/internal/voipmonitor"
	"collector/internal/workload"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

// VoipmonitorLink is kept for lookup/attach APIs; writers use voipmonitor.Link.
type VoipmonitorLink struct {
	DeviceID             uuid.UUID
	SourceSystem         string
	SourceRecordID       uuid.UUID
	SourceCDRID          string
	SourceCallID         string
	SourceProtocolConfID string
	SourceCallIDOutProto string
	PolicyRevision       uint64
	ProjectionSeq        uint64
	VoipmonitorCDRID     string
	VoipmonitorCallID    string
	VoipmonitorCardURL   string
	MatchMethod          string
	MatchScore           uint8
	MatchStatus          string
	MatchEvidenceJSON    string
	MatchedAt            *time.Time
	EventMonth           time.Time
}

func (c *Client) EnqueueVoipmonitorDirtyBuckets(
	ctx context.Context, deviceID uuid.UUID, policyRevision uint64, buckets []time.Time, reason string,
) error {
	if len(buckets) == 0 {
		return nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Ingest)
	if err != nil {
		return err
	}
	defer release()
	now := time.Now().UTC()
	seq := uint64(now.UnixNano())
	if reason == "" {
		reason = "cdr_arrival"
	}
	return c.withBatch(ctx, `INSERT INTO collector.voipmonitor_dirty_buckets
		(device_id,bucket_start,policy_revision,projection_seq,reason,enqueued_at,deleted)`,
		func(batch driver.Batch) error {
			seen := map[time.Time]struct{}{}
			for _, bucket := range buckets {
				hour := bucket.UTC().Truncate(time.Hour)
				if _, ok := seen[hour]; ok {
					continue
				}
				seen[hour] = struct{}{}
				if err := batch.Append(deviceID, hour, policyRevision, seq, reason, now, uint8(0)); err != nil {
					return err
				}
			}
			return nil
		})
}

func (c *Client) WriteVoipmonitorLinks(ctx context.Context, links []voipmonitor.Link) error {
	if len(links) == 0 {
		return nil
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	now := time.Now().UTC()
	return c.withBatch(ctx, `INSERT INTO collector.cdr_voipmonitor_links
		(device_id,event_month,source_system,source_record_id,source_cdr_id,source_call_id,
		source_protocol_conf_id,source_call_id_out_proto,policy_revision,projection_seq,
		voipmonitor_cdr_id,voipmonitor_call_id,voipmonitor_card_url,match_method,match_score,
		match_status,match_evidence_json,matched_at,updated_at,deleted)`,
		func(batch driver.Batch) error {
			for _, link := range links {
				seq := link.ProjectionSeq
				if seq == 0 {
					seq = uint64(now.UnixNano())
				}
				month := link.EventMonth
				if month.IsZero() {
					month = now
				}
				if err := batch.Append(
					link.DeviceID, monthDate(month), link.SourceSystem, link.SourceRecordID,
					link.SourceCDRID, link.SourceCallID, link.SourceProtocolConfID,
					link.SourceCallIDOutProto, link.PolicyRevision, seq,
					link.VoipmonitorCDRID, link.VoipmonitorCallID, link.VoipmonitorCardURL,
					link.MatchMethod, link.MatchScore, link.MatchStatus, link.MatchEvidenceJSON,
					link.MatchedAt, now, uint8(0),
				); err != nil {
					return err
				}
			}
			return nil
		})
}

func (c *Client) LoadVoipmonitorEltexCandidates(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time, policyRevision uint64, limit int,
) ([]voipmonitor.CDRCandidate, error) {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return nil, err
	}
	defer release()
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := c.Conn.Query(ctx, `SELECT c.record_id,
		coalesce(t.setup_time,c.setup_time,c.ingested_at),
		c.duration_ms,c.incoming_cgpn,c.outgoing_cgpn,c.incoming_cdpn,c.outgoing_cdpn,
		ifNull(toString(c.incoming_ip),''),ifNull(toString(c.outgoing_ip),''),
		c.incoming_sip_call_id,c.outgoing_sip_call_id,c.unique_tag,c.release_cause
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		LEFT JOIN collector.cdr_voipmonitor_links_current link
			ON link.device_id=c.device_id AND link.source_system=? AND link.source_record_id=c.record_id
			AND link.policy_revision=?
		WHERE c.device_id=?
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)>=?
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)<?
			AND (link.source_record_id IS NULL OR link.match_status IN ('pending','unmatched'))
		ORDER BY coalesce(t.setup_time,c.setup_time,c.ingested_at) ASC
		LIMIT ?`,
		voipmonitor.SourceEltex, policyRevision, deviceID, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]voipmonitor.CDRCandidate, 0, limit)
	for rows.Next() {
		var item voipmonitor.CDRCandidate
		var durationMS *uint64
		var inA, outA, inB, outB, inSIP, outSIP string
		var inIP, outIP string
		if err := rows.Scan(
			&item.SourceRecordID, &item.SetupTime, &durationMS,
			&inA, &outA, &inB, &outB, &inIP, &outIP, &inSIP, &outSIP, &item.SourceCDRID,
			&item.ReleaseCause,
		); err != nil {
			return nil, err
		}
		item.DeviceID = deviceID
		item.SourceSystem = voipmonitor.SourceEltex
		item.Caller = firstNonEmpty(outA, inA)
		item.Called = firstNonEmpty(outB, inB)
		item.CallerIP = inIP
		item.CalledIP = outIP
		if durationMS != nil {
			sec := int64(*durationMS / 1000)
			item.DurationSec = &sec
		}
		item.SIPCallIDs = nonEmptyStrings(inSIP, outSIP)
		item.SourceCallID = firstNonEmpty(inSIP, outSIP)
		item.EventMonth = item.SetupTime
		out = append(out, item)
	}
	return out, rows.Err()
}

func (c *Client) LoadVoipmonitorSatelCandidates(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time, policyRevision uint64, limit int,
) ([]voipmonitor.CDRCandidate, error) {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return nil, err
	}
	defer release()
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := c.Conn.Query(ctx, `SELECT c.record_id,
		coalesce(t.setup_time,c.setup_time,c.ingested_at),
		c.duration_ms,c.bill_ani,c.bill_dnis,c.in_ani,c.in_dnis,c.out_ani,c.out_dnis,
		c.out_leg_call_id,c.src_out_leg_call_id,c.src_in_leg_conf_id,c.in_leg_call_id,c.conf_id,c.cdr_id
		FROM collector.satel_rtu_cdr AS c FINAL
		LEFT JOIN collector.satel_rtu_cdr_time_facts AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		LEFT JOIN collector.cdr_voipmonitor_links_current link
			ON link.device_id=c.device_id AND link.source_system=? AND link.source_record_id=c.record_id
			AND link.policy_revision=?
		WHERE c.device_id=?
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)>=?
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)<?
			AND (link.source_record_id IS NULL OR link.match_status IN ('pending','unmatched'))
		ORDER BY coalesce(t.setup_time,c.setup_time,c.ingested_at) ASC
		LIMIT ?`,
		voipmonitor.SourceSatel, policyRevision, deviceID, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]voipmonitor.CDRCandidate, 0, limit)
	for rows.Next() {
		var item voipmonitor.CDRCandidate
		var durationMS *uint64
		var billA, billB, inA, inB, outA, outB string
		var outLeg, srcOut, srcConf, inLeg, confID, cdrID string
		if err := rows.Scan(
			&item.SourceRecordID, &item.SetupTime, &durationMS,
			&billA, &billB, &inA, &inB, &outA, &outB,
			&outLeg, &srcOut, &srcConf, &inLeg, &confID, &cdrID,
		); err != nil {
			return nil, err
		}
		item.DeviceID = deviceID
		item.SourceSystem = voipmonitor.SourceSatel
		item.Caller = firstNonEmpty(billA, outA, inA)
		item.Called = firstNonEmpty(billB, outB, inB)
		if durationMS != nil {
			sec := int64(*durationMS / 1000)
			item.DurationSec = &sec
		}
		item.SourceCallIDOutProto = firstNonEmpty(outLeg, srcOut)
		item.SourceProtocolConfID = firstNonEmpty(srcConf, confID)
		item.SourceCallID = firstNonEmpty(inLeg, confID)
		item.SourceCDRID = cdrID
		item.SIPCallIDs = nonEmptyStrings(outLeg, srcOut, srcConf, inLeg, confID)
		item.EventMonth = item.SetupTime
		out = append(out, item)
	}
	return out, rows.Err()
}

func (c *Client) LookupVoipmonitorLink(
	ctx context.Context, deviceID uuid.UUID, sourceSystem string, recordID uuid.UUID,
) (VoipmonitorLink, bool, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return VoipmonitorLink{}, false, err
	}
	defer release()
	var link VoipmonitorLink
	err = c.Conn.QueryRow(ctx, `SELECT device_id,source_system,source_record_id,source_cdr_id,
		source_call_id,source_protocol_conf_id,source_call_id_out_proto,policy_revision,projection_seq,
		voipmonitor_cdr_id,voipmonitor_call_id,voipmonitor_card_url,match_method,match_score,
		match_status,match_evidence_json,matched_at
		FROM collector.cdr_voipmonitor_links_current
		WHERE device_id=? AND source_system=? AND source_record_id=?
		LIMIT 1`, deviceID, sourceSystem, recordID).Scan(
		&link.DeviceID, &link.SourceSystem, &link.SourceRecordID, &link.SourceCDRID,
		&link.SourceCallID, &link.SourceProtocolConfID, &link.SourceCallIDOutProto,
		&link.PolicyRevision, &link.ProjectionSeq, &link.VoipmonitorCDRID, &link.VoipmonitorCallID,
		&link.VoipmonitorCardURL, &link.MatchMethod, &link.MatchScore, &link.MatchStatus,
		&link.MatchEvidenceJSON, &link.MatchedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return VoipmonitorLink{}, false, nil
	}
	if err != nil {
		return VoipmonitorLink{}, false, err
	}
	return link, true, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (c *Client) loadVoipmonitorLinkMap(
	ctx context.Context, deviceID uuid.UUID, sourceSystem string, recordIDs []uuid.UUID,
) (map[uuid.UUID]VoipmonitorLink, error) {
	out := make(map[uuid.UUID]VoipmonitorLink, len(recordIDs))
	if len(recordIDs) == 0 {
		return out, nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return nil, err
	}
	defer release()
	rows, err := c.Conn.Query(ctx, `SELECT source_record_id,voipmonitor_cdr_id,voipmonitor_call_id,
		voipmonitor_card_url,match_status,match_method,match_score
		FROM collector.cdr_voipmonitor_links_current
		WHERE device_id=? AND source_system=? AND source_record_id IN ?`,
		deviceID, sourceSystem, recordIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var link VoipmonitorLink
		if err := rows.Scan(
			&link.SourceRecordID, &link.VoipmonitorCDRID, &link.VoipmonitorCallID,
			&link.VoipmonitorCardURL, &link.MatchStatus, &link.MatchMethod, &link.MatchScore,
		); err != nil {
			return nil, err
		}
		out[link.SourceRecordID] = link
	}
	return out, rows.Err()
}

func (c *Client) AttachVoipmonitorToCallRows(
	ctx context.Context, deviceID uuid.UUID, items []CallRow,
) error {
	ids := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.RecordID)
	}
	links, err := c.loadVoipmonitorLinkMap(ctx, deviceID, voipmonitor.SourceEltex, ids)
	if err != nil {
		return err
	}
	for index := range items {
		if link, ok := links[items[index].RecordID]; ok {
			items[index].VoipmonitorCDRID = link.VoipmonitorCDRID
			items[index].VoipmonitorCallID = link.VoipmonitorCallID
			items[index].VoipmonitorCardURL = link.VoipmonitorCardURL
			items[index].VoipmonitorMatchStatus = link.MatchStatus
			items[index].VoipmonitorMatchMethod = link.MatchMethod
			items[index].VoipmonitorMatchScore = link.MatchScore
		}
	}
	return nil
}

func (c *Client) AttachVoipmonitorToSatelRows(
	ctx context.Context, deviceID uuid.UUID, items []SatelRTUCallRow,
) error {
	ids := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.RecordID)
	}
	links, err := c.loadVoipmonitorLinkMap(ctx, deviceID, voipmonitor.SourceSatel, ids)
	if err != nil {
		return err
	}
	for index := range items {
		if link, ok := links[items[index].RecordID]; ok {
			items[index].VoipmonitorCDRID = link.VoipmonitorCDRID
			items[index].VoipmonitorCallID = link.VoipmonitorCallID
			items[index].VoipmonitorCardURL = link.VoipmonitorCardURL
			items[index].VoipmonitorMatchStatus = link.MatchStatus
			items[index].VoipmonitorMatchMethod = link.MatchMethod
			items[index].VoipmonitorMatchScore = link.MatchScore
		}
	}
	return nil
}
