package analytics

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
)

type DeviceRevisionJob struct {
	DeviceID            uuid.UUID
	Revision            uint64
	Timezone            string
	CDRSourceTimezone   string
	Status              string
	CutoverSealed       uint8
	CursorReceivedAt    time.Time
	CursorEventID       uuid.UUID
	CursorReceivedUS    int64
	CDRCursorIngestedAt time.Time
	CDRCursorRecordID   uuid.UUID
	CDRCursorIngestedUS int64
	HighWatermark       time.Time
	HighWatermarkUS     int64
	CDRHighWatermark    time.Time
	CDRHighWatermarkUS  int64
	RawTotal            uint64
	CDRTotal            uint64
	Processed           uint64
	CDRProcessed        uint64
	LifecycleCount      uint64
	Error               string
	UpdatedAt           time.Time
}

func (c *Client) ScheduleDeviceRebuild(
	ctx context.Context, deviceID uuid.UUID, revision uint64, timezone string,
) error {
	if _, err := time.LoadLocation(timezone); err != nil {
		return fmt.Errorf("invalid device timezone %q: %w", timezone, err)
	}
	var existingStatus string
	err := c.Conn.QueryRow(ctx, `SELECT status
		FROM collector.device_derived_revisions FINAL
		WHERE device_id=? AND revision=? LIMIT 1`, deviceID, revision).Scan(&existingStatus)
	if err == nil && (existingStatus == "building" || existingStatus == "cutover" ||
		existingStatus == "ready" || existingStatus == "active") {
		return nil
	}
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "no rows") {
		return err
	}
	var syslogHigh, cdrHigh time.Time
	var rawTotal, cdrTotal uint64
	job := DeviceRevisionJob{}
	if err := c.Conn.QueryRow(ctx, `SELECT
		coalesce(max(received_at),toDateTime64(0,6,'UTC')),
		ifNull(max(toUnixTimestamp64Micro(received_at)),0),countDistinct(event_id)
		FROM collector.raw_syslog WHERE device_id=?`, deviceID).
		Scan(&syslogHigh, &job.HighWatermarkUS, &rawTotal); err != nil {
		return err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT
		coalesce(max(ingested_at),toDateTime64(0,6,'UTC')),
		ifNull(max(toUnixTimestamp64Micro(ingested_at)),0),countDistinct(record_id)
		FROM collector.cdr_records WHERE device_id=?`, deviceID).
		Scan(&cdrHigh, &job.CDRHighWatermarkUS, &cdrTotal); err != nil {
		return err
	}
	job.DeviceID = deviceID
	job.Revision = revision
	job.Timezone = timezone
	job.CDRSourceTimezone = timezone
	job.Status = "building"
	job.HighWatermark = syslogHigh
	job.CDRHighWatermark = cdrHigh
	job.RawTotal = rawTotal
	job.CDRTotal = cdrTotal
	job.UpdatedAt = time.Now().UTC()
	return c.writeDeviceRevisionJob(ctx, job)
}

func (c *Client) ListBuildingDeviceRevisions(ctx context.Context) ([]DeviceRevisionJob, error) {
	rows, err := c.Conn.Query(ctx, `SELECT
		device_id,revision,timezone,cdr_source_timezone,status,cutover_sealed,
		cursor_received_at,cursor_event_id,
		cursor_received_us,cdr_cursor_ingested_at,cdr_cursor_record_id,
		cdr_cursor_ingested_us,high_watermark,high_watermark_us,
		cdr_high_watermark,cdr_high_watermark_us,
		raw_total,cdr_total,processed,cdr_processed,lifecycle_count,error,updated_at
		FROM collector.device_derived_revisions FINAL
		WHERE status IN ('building','cutover') ORDER BY updated_at LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]DeviceRevisionJob, 0)
	for rows.Next() {
		var item DeviceRevisionJob
		if err := rows.Scan(
			&item.DeviceID, &item.Revision, &item.Timezone, &item.CDRSourceTimezone, &item.Status,
			&item.CutoverSealed,
			&item.CursorReceivedAt, &item.CursorEventID, &item.CursorReceivedUS,
			&item.CDRCursorIngestedAt, &item.CDRCursorRecordID,
			&item.CDRCursorIngestedUS, &item.HighWatermark, &item.HighWatermarkUS,
			&item.CDRHighWatermark, &item.CDRHighWatermarkUS,
			&item.RawTotal, &item.CDRTotal, &item.Processed, &item.CDRProcessed,
			&item.LifecycleCount, &item.Error, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) NextDeviceRevisionSyslogBatch(
	ctx context.Context, job DeviceRevisionJob, limit uint64,
) ([]ReplaySyslogRow, error) {
	rows, err := c.Conn.Query(ctx, `SELECT
		event_id,device_id,received_at,toUnixTimestamp64Micro(received_at),
		source_ip,source_port,payload,source_timezone
		FROM collector.raw_syslog
		WHERE device_id=? AND toUnixTimestamp64Micro(received_at)<=?
		  AND (toUnixTimestamp64Micro(received_at)>?
			OR (toUnixTimestamp64Micro(received_at)=? AND event_id>?))
		ORDER BY received_at,event_id LIMIT 1 BY event_id LIMIT ?`,
		job.DeviceID, job.HighWatermarkUS, job.CursorReceivedUS, job.CursorReceivedUS,
		job.CursorEventID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ReplaySyslogRow, 0, limit)
	for rows.Next() {
		var item ReplaySyslogRow
		var payload string
		var sourceIP net.IP
		if err := rows.Scan(
			&item.EventID, &item.DeviceID, &item.ReceivedAt, &item.ReceivedAtUS, &sourceIP,
			&item.SourcePort, &payload, &item.SourceTimezone,
		); err != nil {
			return nil, err
		}
		item.SourceIP = sourceIP
		item.Payload = []byte(payload)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (c *Client) AdvanceDeviceRevisionSyslog(
	ctx context.Context, job DeviceRevisionJob, rows []ReplaySyslogRow,
) error {
	if len(rows) == 0 {
		return nil
	}
	last := rows[len(rows)-1]
	job.CursorReceivedAt = last.ReceivedAt
	job.CursorReceivedUS = last.ReceivedAtUS
	job.CursorEventID = last.EventID
	job.Processed += uint64(len(rows))
	job.UpdatedAt = time.Now().UTC()
	return c.writeDeviceRevisionJob(ctx, job)
}

func (c *Client) RebuildCDRTimeChunk(
	ctx context.Context, job DeviceRevisionJob, limit uint64,
) (DeviceRevisionJob, bool, error) {
	var upperTime time.Time
	var upperID uuid.UUID
	var upperUS int64
	err := c.Conn.QueryRow(ctx, `SELECT ingested_at,record_id,
		toUnixTimestamp64Micro(ingested_at)
		FROM collector.cdr_records
		WHERE device_id=? AND toUnixTimestamp64Micro(ingested_at)<=?
		  AND (toUnixTimestamp64Micro(ingested_at)>?
			OR (toUnixTimestamp64Micro(ingested_at)=? AND record_id>?))
		ORDER BY ingested_at,record_id LIMIT 1 OFFSET ?`,
		job.DeviceID, job.CDRHighWatermarkUS, job.CDRCursorIngestedUS,
		job.CDRCursorIngestedUS, job.CDRCursorRecordID, limit-1).
		Scan(&upperTime, &upperID, &upperUS)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			var firstTime time.Time
			var firstID uuid.UUID
			var firstUS int64
			firstErr := c.Conn.QueryRow(ctx, `SELECT ingested_at,record_id,
				toUnixTimestamp64Micro(ingested_at)
				FROM collector.cdr_records
				WHERE device_id=? AND toUnixTimestamp64Micro(ingested_at)<=?
				  AND (toUnixTimestamp64Micro(ingested_at)>?
					OR (toUnixTimestamp64Micro(ingested_at)=? AND record_id>?))
				ORDER BY ingested_at,record_id LIMIT 1`,
				job.DeviceID, job.CDRHighWatermarkUS, job.CDRCursorIngestedUS,
				job.CDRCursorIngestedUS, job.CDRCursorRecordID).
				Scan(&firstTime, &firstID, &firstUS)
			if firstErr != nil {
				if strings.Contains(strings.ToLower(firstErr.Error()), "no rows") {
					return job, true, nil
				}
				return job, false, firstErr
			}
			upperTime, upperID, upperUS = job.CDRHighWatermark,
				uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"),
				job.CDRHighWatermarkUS
		}
	}
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.cdr_time_facts
		(device_id,timezone_revision,record_id,interpreted_at,setup_wall_clock,
		 connect_wall_clock,disconnect_wall_clock,setup_time_utc,connect_time_utc,
		 disconnect_time_utc,source_timezone,source_utc_offset_minutes)
		SELECT device_id,?,record_id,now64(6),
			coalesce(nullIf(raw_fields['setup_time'],''),nullIf(raw_fields['setup'],''),''),
			coalesce(nullIf(raw_fields['connect_time'],''),nullIf(raw_fields['connect'],''),''),
			coalesce(nullIf(raw_fields['disconnect_time'],''),nullIf(raw_fields['disconnect'],''),''),
			parseDateTime64BestEffortOrNull(coalesce(nullIf(raw_fields['setup_time'],''),
				nullIf(raw_fields['setup'],'')),6,?),
			parseDateTime64BestEffortOrNull(coalesce(nullIf(raw_fields['connect_time'],''),
				nullIf(raw_fields['connect'],'')),6,?),
			parseDateTime64BestEffortOrNull(coalesce(nullIf(raw_fields['disconnect_time'],''),
				nullIf(raw_fields['disconnect'],'')),6,?),
			?,toInt16(ifNull(dateDiff('minute',
				parseDateTime64BestEffortOrNull(coalesce(nullIf(raw_fields['setup_time'],''),
					nullIf(raw_fields['setup'],'')),6,?),
				parseDateTime64BestEffortOrNull(coalesce(nullIf(raw_fields['setup_time'],''),
					nullIf(raw_fields['setup'],'')),6,'UTC')),0))
		FROM collector.cdr_records
		WHERE device_id=? AND toUnixTimestamp64Micro(ingested_at)<=?
		  AND (toUnixTimestamp64Micro(ingested_at)>?
			OR (toUnixTimestamp64Micro(ingested_at)=? AND record_id>?))
		  AND (toUnixTimestamp64Micro(ingested_at)<?
			OR (toUnixTimestamp64Micro(ingested_at)=? AND record_id<=?))`,
		job.Revision, job.CDRSourceTimezone, job.CDRSourceTimezone,
		job.CDRSourceTimezone, job.CDRSourceTimezone,
		job.CDRSourceTimezone, job.DeviceID, job.CDRHighWatermarkUS, job.CDRCursorIngestedUS,
		job.CDRCursorIngestedUS, job.CDRCursorRecordID, upperUS, upperUS, upperID,
	); err != nil {
		return job, false, err
	}
	var count uint64
	if err := c.Conn.QueryRow(ctx, `SELECT count() FROM collector.cdr_records
		WHERE device_id=? AND toUnixTimestamp64Micro(ingested_at)<=?
		  AND (toUnixTimestamp64Micro(ingested_at)>?
			OR (toUnixTimestamp64Micro(ingested_at)=? AND record_id>?))
		  AND (toUnixTimestamp64Micro(ingested_at)<?
			OR (toUnixTimestamp64Micro(ingested_at)=? AND record_id<=?))`,
		job.DeviceID, job.CDRHighWatermarkUS, job.CDRCursorIngestedUS,
		job.CDRCursorIngestedUS, job.CDRCursorRecordID, upperUS, upperUS, upperID).
		Scan(&count); err != nil {
		return job, false, err
	}
	job.CDRCursorIngestedAt, job.CDRCursorRecordID = upperTime, upperID
	job.CDRCursorIngestedUS = upperUS
	job.CDRProcessed += count
	job.UpdatedAt = time.Now().UTC()
	if err := c.writeDeviceRevisionJob(ctx, job); err != nil {
		return job, false, err
	}
	return job, count < limit, nil
}

func (c *Client) MarkDeviceRevisionReady(
	ctx context.Context, job DeviceRevisionJob,
) (DeviceRevisionJob, error) {
	if job.Processed < job.RawTotal || job.CDRProcessed < job.CDRTotal {
		return job, fmt.Errorf("revision coverage incomplete: syslog %d/%d CDR %d/%d",
			job.Processed, job.RawTotal, job.CDRProcessed, job.CDRTotal)
	}
	if err := c.Conn.QueryRow(ctx, `SELECT count()
		FROM collector.antifraud_lifecycles FINAL
		WHERE device_id=? AND timezone_revision=? AND is_antifraud=1`,
		job.DeviceID, job.Revision).Scan(&job.LifecycleCount); err != nil {
		return job, err
	}
	job.Status = "ready"
	job.UpdatedAt = time.Now().UTC()
	return job, c.writeDeviceRevisionJob(ctx, job)
}

func (c *Client) BeginDeviceRevisionCutover(
	ctx context.Context, job DeviceRevisionJob,
) error {
	job.Status = "cutover"
	job.UpdatedAt = time.Now().UTC()
	return c.writeDeviceRevisionJob(ctx, job)
}

func (c *Client) SupersedeDeviceRevision(
	ctx context.Context, job DeviceRevisionJob, reason string,
) error {
	job.Status = "superseded"
	job.Error = reason
	job.UpdatedAt = time.Now().UTC()
	return c.writeDeviceRevisionJob(ctx, job)
}

func (c *Client) RefreshDeviceRevisionHighWatermarks(
	ctx context.Context, job DeviceRevisionJob,
) (DeviceRevisionJob, bool, error) {
	if job.CutoverSealed != 0 {
		return job, false, nil
	}
	var syslogHigh, cdrHigh time.Time
	var rawTotal, cdrTotal uint64
	if err := c.Conn.QueryRow(ctx, `SELECT
		coalesce(max(received_at),toDateTime64(0,6,'UTC')),
		ifNull(max(toUnixTimestamp64Micro(received_at)),0),countDistinct(event_id)
		FROM collector.raw_syslog WHERE device_id=?`, job.DeviceID).
		Scan(&syslogHigh, &job.HighWatermarkUS, &rawTotal); err != nil {
		return job, false, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT
		coalesce(max(ingested_at),toDateTime64(0,6,'UTC')),
		ifNull(max(toUnixTimestamp64Micro(ingested_at)),0),countDistinct(record_id)
		FROM collector.cdr_records WHERE device_id=?`, job.DeviceID).
		Scan(&cdrHigh, &job.CDRHighWatermarkUS, &cdrTotal); err != nil {
		return job, false, err
	}
	job.HighWatermark, job.RawTotal = syslogHigh, rawTotal
	job.CDRHighWatermark, job.CDRTotal = cdrHigh, cdrTotal
	job.CutoverSealed = 1
	job.UpdatedAt = time.Now().UTC()
	return job, true, c.writeDeviceRevisionJob(ctx, job)
}

func (c *Client) ActivateDeviceRevision(ctx context.Context, job DeviceRevisionJob) error {
	job.Status = "active"
	job.UpdatedAt = time.Now().UTC()
	if err := c.writeDeviceRevisionJob(ctx, job); err != nil {
		return err
	}
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.device_derived_revisions
		(device_id,revision,timezone,status,cursor_received_at,cursor_event_id,
		 cursor_received_us,cdr_cursor_ingested_at,cdr_cursor_record_id,
		 cdr_cursor_ingested_us,high_watermark,high_watermark_us,
		 cdr_high_watermark,cdr_high_watermark_us,raw_total,cdr_total,processed,
		 cdr_processed,lifecycle_count,error,updated_at,cdr_source_timezone,cutover_sealed)
		SELECT device_id,revision,timezone,'superseded',cursor_received_at,cursor_event_id,
			cursor_received_us,cdr_cursor_ingested_at,cdr_cursor_record_id,
			cdr_cursor_ingested_us,high_watermark,high_watermark_us,
			cdr_high_watermark,cdr_high_watermark_us,raw_total,cdr_total,processed,
			cdr_processed,lifecycle_count,'replaced by newer active revision',now64(6),
			cdr_source_timezone,cutover_sealed
		FROM collector.device_derived_revisions FINAL
		WHERE device_id=? AND revision!=? AND status='active'`,
		job.DeviceID, job.Revision); err != nil {
		return err
	}
	return c.EnqueueDeviceDirtyDays(ctx, job.DeviceID, job.Revision)
}

func (c *Client) writeDeviceRevisionJob(ctx context.Context, job DeviceRevisionJob) error {
	return c.Conn.Exec(ctx, `INSERT INTO collector.device_derived_revisions
		(device_id,revision,timezone,cdr_source_timezone,status,cutover_sealed,
		 cursor_received_at,cursor_event_id,
		 cursor_received_us,cdr_cursor_ingested_at,cdr_cursor_record_id,
		 cdr_cursor_ingested_us,high_watermark,high_watermark_us,
		 cdr_high_watermark,cdr_high_watermark_us,
		 raw_total,cdr_total,processed,cdr_processed,lifecycle_count,error,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		job.DeviceID, job.Revision, job.Timezone, job.CDRSourceTimezone, job.Status,
		job.CutoverSealed, job.CursorReceivedAt,
		job.CursorEventID, job.CursorReceivedUS, job.CDRCursorIngestedAt,
		job.CDRCursorRecordID, job.CDRCursorIngestedUS, job.HighWatermark,
		job.HighWatermarkUS, job.CDRHighWatermark, job.CDRHighWatermarkUS,
		job.RawTotal, job.CDRTotal,
		job.Processed, job.CDRProcessed, job.LifecycleCount, job.Error, job.UpdatedAt)
}

func (c *Client) EnqueueDeviceDirtyDays(
	ctx context.Context, deviceID uuid.UUID, revision uint64,
) error {
	return c.Conn.Exec(ctx, `INSERT INTO collector.correlation_dirty_buckets
		(device_id,timezone_revision,bucket,status,attempts,error,updated_at)
		SELECT device_id,timezone_revision,toDate(first_event_at),'pending',toUInt16(0),'',now64(6)
		FROM collector.antifraud_lifecycles FINAL
		WHERE device_id=? AND timezone_revision=?
		GROUP BY device_id,timezone_revision,toDate(first_event_at)`,
		deviceID, revision)
}
