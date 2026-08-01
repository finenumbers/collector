package analytics

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"collector/internal/equipment"
	"collector/internal/workload"

	"github.com/google/uuid"
)

type ExportSnapshot struct {
	Revision      uint64
	HighWatermark *time.Time
	HighID        *uuid.UUID
	EstimatedRows *int64
	ParserVersion string
}

const (
	ExportEstimateLimit   = int64(250_000)
	exportEstimateTimeout = 2 * time.Second
	exportSnapshotTimeout = 5 * time.Second
)

// PinExportSnapshot captures the derived revision and raw upper boundary used
// by a queued export. Estimates are deliberately capped by the caller's later
// format decision; they are not used as correctness boundaries.
func (c *Client) PinExportSnapshot(
	ctx context.Context, deviceID uuid.UUID, revision uint64, dataset, template, timezone string,
	category, search string, rangeFrom, rangeTo *time.Time,
) (ExportSnapshot, error) {
	ctx, release, err := c.queryContext(ctx, workload.Export)
	if err != nil {
		return ExportSnapshot{}, err
	}
	defer release()
	result := ExportSnapshot{Revision: revision}
	if timezone == "" {
		timezone = "UTC"
	}
	high, id := time.Unix(0, 0).UTC(), uuid.Nil
	snapshotCtx, cancelSnapshot := context.WithTimeout(ctx, exportSnapshotTimeout)
	defer cancelSnapshot()
	switch dataset {
	case "syslog":
		err = c.queryRow(snapshotCtx, `SELECT received_at,event_id
			FROM collector.syslog_messages FINAL WHERE device_id=?
			ORDER BY received_at DESC,event_id DESC LIMIT 1`, deviceID).Scan(&high, &id)
	case "calls":
		result.ParserVersion = template
		if template == equipment.TemplateSatelRTUCDRV1 {
			result.ParserVersion = SatelRTUParserVersion
			err = c.queryRow(snapshotCtx, `WITH times AS (
				SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time,
					argMax(cdr_date_utc,interpreted_at) AS cdr_date
				FROM collector.satel_rtu_cdr_time_facts
				WHERE device_id=? AND timezone_revision=? GROUP BY record_id
			)
			SELECT coalesce(t.setup_time,t.cdr_date,c.ingested_at) AS sort_time,c.record_id
			FROM collector.satel_rtu_cdr AS c FINAL
			LEFT JOIN times AS t ON t.record_id=c.record_id
			WHERE c.device_id=? AND c.timezone_revision=?
			ORDER BY sort_time DESC,c.record_id DESC LIMIT 1`,
				deviceID, revision, deviceID, revision).Scan(&high, &id)
		} else {
			err = c.queryRow(snapshotCtx, `SELECT
				coalesce(parseDateTime64BestEffortOrNull(
					coalesce(nullIf(raw_fields['setup_time'],''),nullIf(raw_fields['setup'],'')),
					6,?),ingested_at) AS sort_time,record_id
				FROM collector.cdr_records WHERE device_id=?
				ORDER BY sort_time DESC,record_id DESC LIMIT 1`,
				timezone, deviceID).Scan(&high, &id)
		}
	case "antifraud":
		err = c.queryRow(snapshotCtx, `SELECT first_seen_at,call_id
			FROM collector.custom_antifraud_calls_current WHERE device_id=?
			ORDER BY first_seen_at DESC,call_id DESC LIMIT 1`, deviceID).Scan(&high, &id)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ExportSnapshot{}, err
	}
	result.HighWatermark, result.HighID = &high, &id
	result.EstimatedRows = c.estimateExportRows(
		ctx, deviceID, revision, dataset, template, category, search, timezone,
		rangeFrom, rangeTo, high, id,
	)
	return result, nil
}

func (c *Client) estimateExportRows(
	ctx context.Context, deviceID uuid.UUID, revision uint64, dataset, template,
	category, search, timezone string, rangeFrom, rangeTo *time.Time,
	high time.Time, highID uuid.UUID,
) *int64 {
	if search != "" {
		return nil
	}
	var source, sortColumn, idColumn string
	args := []any{}
	switch dataset {
	case "syslog":
		source, sortColumn, idColumn = "collector.syslog_messages FINAL", "received_at", "event_id"
		args = append(args, deviceID)
		source += " WHERE device_id=?"
	case "calls":
		idColumn = "record_id"
		if template == equipment.TemplateSatelRTUCDRV1 {
			sortColumn = "sort_time"
			source = `(WITH times AS (
				SELECT record_id,argMax(setup_time_utc,interpreted_at) AS setup_time,
					argMax(cdr_date_utc,interpreted_at) AS cdr_date
				FROM collector.satel_rtu_cdr_time_facts
				WHERE device_id=? AND timezone_revision=? GROUP BY record_id
			) SELECT c.record_id,coalesce(t.setup_time,t.cdr_date,c.ingested_at) AS sort_time
			FROM collector.satel_rtu_cdr AS c FINAL
			LEFT JOIN times AS t ON t.record_id=c.record_id
			WHERE c.device_id=? AND c.timezone_revision=?)`
			args = append(args, deviceID, revision, deviceID, revision)
		} else {
			sortColumn = "sort_time"
			source = `(SELECT record_id,coalesce(parseDateTime64BestEffortOrNull(
				coalesce(nullIf(raw_fields['setup_time'],''),nullIf(raw_fields['setup'],'')),
				6,?),ingested_at) AS sort_time
				FROM collector.cdr_records WHERE device_id=?)`
			args = append(args, timezone, deviceID)
		}
	case "antifraud":
		source, sortColumn, idColumn = "collector.custom_antifraud_calls_current", "first_seen_at", "call_id"
		args = append(args, deviceID)
		source += " WHERE device_id=?"
	default:
		return nil
	}
	query := `SELECT count() FROM (SELECT 1 FROM ` + source + ` WHERE 1`
	if dataset == "syslog" || dataset == "antifraud" {
		query = `SELECT count() FROM (SELECT 1 FROM ` + source
	}
	if rangeFrom != nil {
		query += ` AND ` + sortColumn + `>=?`
		args = append(args, *rangeFrom)
	}
	if rangeTo != nil {
		query += ` AND ` + sortColumn + `<?`
		args = append(args, *rangeTo)
	}
	query += ` AND (` + sortColumn + `<? OR (` + sortColumn + `=? AND ` + idColumn + `<=?))`
	args = append(args, high, high, highID, ExportEstimateLimit+1)
	query += ` LIMIT ?)`
	estimateCtx, cancel := context.WithTimeout(ctx, exportEstimateTimeout)
	defer cancel()
	var count int64
	err := c.queryRow(estimateCtx, query, args...).Scan(&count)
	return normalizeExportEstimate(count, err)
}

func normalizeExportEstimate(count int64, err error) *int64 {
	if err != nil || count < 0 || count > ExportEstimateLimit {
		return nil
	}
	return &count
}

func (c *Client) ListExportCallsPage(
	ctx context.Context, deviceID uuid.UUID, _ uint64, search string,
	limit uint64, cursor *CallCursor, timeRange *TimeRange, filters EltexColumnFilters,
) (CallPage, error) {
	return c.ListCallsPageRange(ctx, deviceID, search, limit, cursor, timeRange, filters)
}

func (c *Client) ListExportSatelRTUCallsPage(
	ctx context.Context, deviceID uuid.UUID, revision uint64, search string,
	limit uint64, cursor *CallCursor, timeRange *TimeRange, filters SatelColumnFilters,
) (SatelRTUCallPage, error) {
	return c.listSatelRTUCallsPage(
		ctx, deviceID, &revision, search, limit, cursor, timeRange, filters,
	)
}
