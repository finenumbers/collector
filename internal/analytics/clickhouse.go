package analytics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"collector/internal/redact"
	"collector/internal/workload"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

type Client struct {
	Conn        clickhouse.Conn
	Admission   *workload.Manager
	admissionMu sync.Mutex
}

type DeviceStats struct {
	Calls24h          uint64  `json:"calls24h"`
	FailedCalls24h    uint64  `json:"failedCalls24h"`
	AverageTalkMS     float64 `json:"averageTalkMs"`
	SyslogMessages24h uint64  `json:"syslogMessages24h"`
}

// TimeRange is a half-open UTC interval used by every dated read model.
// Callers are responsible for deriving it from the device's active timezone.
type TimeRange struct {
	From time.Time
	To   time.Time
}

type CallRow struct {
	RecordID                      uuid.UUID  `json:"recordId"`
	SetupTime                     *time.Time `json:"setupTime"`
	ConnectTime                   *time.Time `json:"connectTime,omitempty"`
	DisconnectTime                *time.Time `json:"disconnectTime,omitempty"`
	DurationMS                    *uint64    `json:"durationMs"`
	ReleaseCause                  *uint16    `json:"releaseCause"`
	ReleaseInfo                   string     `json:"releaseInfo"`
	ReleaseSide                   string     `json:"releaseSide,omitempty"`
	IncomingIP                    string     `json:"incomingIp,omitempty"`
	OutgoingIP                    string     `json:"outgoingIp,omitempty"`
	IncomingType                  string     `json:"incomingType,omitempty"`
	OutgoingType                  string     `json:"outgoingType,omitempty"`
	IncomingDescription           string     `json:"incomingDescription"`
	OutgoingDescription           string     `json:"outgoingDescription"`
	IncomingCgPN                  string     `json:"incomingCgpn"`
	OutgoingCgPN                  string     `json:"outgoingCgpn"`
	IncomingCdPN                  string     `json:"incomingCdpn"`
	OutgoingCdPN                  string     `json:"outgoingCdpn"`
	IncomingRedirectingNumber     string     `json:"incomingRedirectingNumber,omitempty"`
	OutgoingRedirectingNumber     string     `json:"outgoingRedirectingNumber,omitempty"`
	IncomingNumplan               string     `json:"incomingNumplan,omitempty"`
	OutgoingNumplan               string     `json:"outgoingNumplan,omitempty"`
	CallingNAI                    string     `json:"callingNai,omitempty"`
	CalledNAI                     string     `json:"calledNai,omitempty"`
	IncomingE1Stream              string     `json:"incomingE1Stream,omitempty"`
	IncomingE1Channel             string     `json:"incomingE1Channel,omitempty"`
	OutgoingE1Stream              string     `json:"outgoingE1Stream,omitempty"`
	OutgoingE1Channel             string     `json:"outgoingE1Channel,omitempty"`
	IncomingSIPCallID             string     `json:"incomingSipCallId,omitempty"`
	OutgoingSIPCallID             string     `json:"outgoingSipCallId,omitempty"`
	IncomingSS7CIC                *uint32    `json:"incomingSs7Cic,omitempty"`
	OutgoingSS7CIC                *uint32    `json:"outgoingSs7Cic,omitempty"`
	RadiusSessionID               string     `json:"radiusSessionId"`
	RadiusSessionIDNormalized     string     `json:"radiusSessionIdNormalized,omitempty"`
	GlobalCallref                 string     `json:"globalCallref,omitempty"`
	UniqueTag                     string     `json:"uniqueTag"`
	TransferMark                  string     `json:"transferMark,omitempty"`
	RejectingRadiusServer         string     `json:"rejectingRadiusServer,omitempty"`
	SequenceNumber                string     `json:"sequenceNumber,omitempty"`
	BootEpoch                     string     `json:"bootEpoch,omitempty"`
	Sequence                      uint64     `json:"sequence,omitempty"`
	SetupTimeLocal                string     `json:"setupTimeLocal"`
	SourceTimezone                string     `json:"sourceTimezone"`
	SourceUTCOffsetMinutes        int16      `json:"sourceUtcOffsetMinutes,omitempty"`
	SortTime                      time.Time  `json:"-"`
}

type CallCursor struct {
	SortTime time.Time
	RecordID uuid.UUID
}

type CallPage struct {
	Items   []CallRow
	HasMore bool
}

type CDRRecord struct {
	RecordID, DeviceID, FileID                 uuid.UUID
	RowNumber                                  uint64
	IngestedAt                                 time.Time
	SequenceNumber, BootEpoch                  string
	Sequence                                   uint64
	SetupTime, ConnectTime, DisconnectTime     *time.Time
	DurationMS                                 *uint64
	ReleaseCause                               *uint16
	ReleaseInfo, ReleaseSide                   string
	IncomingIP, OutgoingIP                     *net.IP
	IncomingType, OutgoingType                 string
	IncomingDescription, OutgoingDescription   string
	IncomingCgPN, OutgoingCgPN                 string
	IncomingCdPN, OutgoingCdPN                 string
	IncomingRedirectingNumber                  string
	OutgoingRedirectingNumber                  string
	IncomingNumplan, OutgoingNumplan           string
	CallingNAI, CalledNAI                      string
	IncomingE1Stream, IncomingE1Channel        string
	OutgoingE1Stream, OutgoingE1Channel        string
	IncomingSIPCallID, OutgoingSIPCallID       string
	IncomingSS7CIC, OutgoingSS7CIC             *uint32
	RadiusSessionID, RadiusSessionIDNormalized string
	GlobalCallref, UniqueTag, TransferMark     string
	RejectingRadiusServer                      string
	RawFields                                  map[string]string
	SourceTimezone                             string
	SourceUTCOffsetMinutes                     int16
	TimezoneRevision                           uint64
}

func Open(addr, database, username, password string) (*Client, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: database, Username: username, Password: password},
		// DialTimeout also bounds pool acquisition wait when MaxOpenConns is saturated.
		DialTimeout:     30 * time.Second,
		MaxOpenConns:    32,
		MaxIdleConns:    16,
		ConnMaxLifetime: time.Hour,
		Compression:     &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, err
	}
	return &Client{Conn: conn, Admission: workload.New(workload.Options{})}, nil
}

func (c *Client) Migrate(
	ctx context.Context, directory string, migrationOptions ...MigrationOptions,
) error {
	options := MigrationOptions{}
	if len(migrationOptions) > 0 {
		options = migrationOptions[0]
	}
	if options.DeploymentLocker == nil {
		if options.RequireDeploymentLock {
			return errors.New("ClickHouse migration deployment lock is required")
		}
	} else {
		release, err := options.DeploymentLocker.LockClickHouseMigrations(ctx)
		if err != nil {
			return fmt.Errorf("acquire ClickHouse migration deployment lock: %w", err)
		}
		defer release()
	}
	if err := c.Conn.Exec(ctx, `CREATE DATABASE IF NOT EXISTS collector`); err != nil {
		return err
	}
	if err := c.Conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS collector.schema_migrations
		(version String, applied_at DateTime64(3, 'UTC'))
		ENGINE = ReplacingMergeTree(applied_at) ORDER BY version`); err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		var applied uint64
		if err := c.Conn.QueryRow(ctx,
			`SELECT count() FROM collector.schema_migrations WHERE version=?`, entry.Name()).
			Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		if entry.Name() == "022_syslog_messages.sql" && options.StopBeforeCopy {
			return nil
		}
		if entry.Name() == "023_remove_legacy_syslog_model.sql" {
			if options.StopBeforeCleanup {
				return nil
			}
			report, err := c.PreflightLegacySyslogCleanup(ctx, options)
			if err != nil {
				return fmt.Errorf("%s preflight: %w", entry.Name(), err)
			}
			if err := report.Validate(); err != nil {
				return fmt.Errorf("%s refused destructive cleanup: %w", entry.Name(), err)
			}
		}
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		for _, statement := range strings.Split(string(content), ";") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if err := c.Conn.Exec(ctx, statement); err != nil {
				return fmt.Errorf("%s: %w", entry.Name(), err)
			}
		}
		if err := c.Conn.Exec(ctx,
			`INSERT INTO collector.schema_migrations(version,applied_at) VALUES(?,now64(3))`,
			entry.Name()); err != nil {
			return fmt.Errorf("%s: recording migration: %w", entry.Name(), err)
		}
	}
	return nil
}

func (c *Client) InsertCDRBatch(ctx context.Context, records []CDRRecord) error {
	if len(records) == 0 {
		return nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Ingest)
	if err != nil {
		return err
	}
	defer release()
	if err := c.withBatch(ctx, `INSERT INTO collector.cdr_records
		(record_id,device_id,file_id,row_number,ingested_at,sequence_number,boot_epoch,sequence,
		 setup_time,connect_time,disconnect_time,duration_ms,release_cause,release_info,
		 release_side,incoming_ip,outgoing_ip,incoming_type,outgoing_type,incoming_description,
		 outgoing_description,incoming_cgpn,outgoing_cgpn,incoming_cdpn,outgoing_cdpn,
		 incoming_redirecting_number,outgoing_redirecting_number,incoming_numplan,outgoing_numplan,
		 calling_nai,called_nai,incoming_e1_stream,incoming_e1_channel,outgoing_e1_stream,
		 outgoing_e1_channel,incoming_sip_call_id,outgoing_sip_call_id,incoming_ss7_cic,
		 outgoing_ss7_cic,radius_session_id,radius_session_id_normalized,global_callref,
		 unique_tag,transfer_mark,rejecting_radius_server,raw_fields,source_timezone,
		 source_utc_offset_minutes)`, func(batch driver.Batch) error {
		for _, record := range records {
			if err := batch.Append(
				record.RecordID, record.DeviceID, record.FileID, record.RowNumber, record.IngestedAt,
				record.SequenceNumber, record.BootEpoch, record.Sequence, record.SetupTime,
				record.ConnectTime, record.DisconnectTime, record.DurationMS, record.ReleaseCause,
				record.ReleaseInfo, record.ReleaseSide, record.IncomingIP, record.OutgoingIP,
				record.IncomingType, record.OutgoingType, record.IncomingDescription,
				record.OutgoingDescription, record.IncomingCgPN, record.OutgoingCgPN,
				record.IncomingCdPN, record.OutgoingCdPN, record.IncomingRedirectingNumber,
				record.OutgoingRedirectingNumber, record.IncomingNumplan, record.OutgoingNumplan,
				record.CallingNAI, record.CalledNAI, record.IncomingE1Stream,
				record.IncomingE1Channel, record.OutgoingE1Stream, record.OutgoingE1Channel,
				record.IncomingSIPCallID, record.OutgoingSIPCallID,
				record.IncomingSS7CIC, record.OutgoingSS7CIC,
				record.RadiusSessionID, record.RadiusSessionIDNormalized, record.GlobalCallref,
				record.UniqueTag, record.TransferMark, record.RejectingRadiusServer,
				redactStringMap(record.RawFields),
				record.SourceTimezone, record.SourceUTCOffsetMinutes,
			); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := c.InsertCDRTimeInterpretationsBatch(ctx, records); err != nil {
		return err
	}
	return nil
}

func (c *Client) InsertCDRTimeInterpretationsBatch(
	ctx context.Context, records []CDRRecord,
) error {
	if len(records) == 0 {
		return nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Ingest)
	if err != nil {
		return err
	}
	defer release()
	now := time.Now().UTC()
	if err := c.withBatch(ctx, `INSERT INTO collector.cdr_time_interpretations
		(record_id,device_id,interpreted_at,setup_time,connect_time,disconnect_time,
		 source_timezone,source_utc_offset_minutes)`, func(batch driver.Batch) error {
		for _, record := range records {
			if err := batch.Append(
				record.RecordID, record.DeviceID, now, record.SetupTime, record.ConnectTime,
				record.DisconnectTime, record.SourceTimezone, record.SourceUTCOffsetMinutes,
			); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return c.InsertCDRTimeFactsBatch(ctx, records)
}

func (c *Client) InsertCDRTimeFactsBatch(ctx context.Context, records []CDRRecord) error {
	if len(records) == 0 {
		return nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Ingest)
	if err != nil {
		return err
	}
	defer release()
	now := time.Now().UTC()
	return c.withBatch(ctx, `INSERT INTO collector.cdr_time_facts
		(device_id,timezone_revision,record_id,interpreted_at,setup_wall_clock,
		 connect_wall_clock,disconnect_wall_clock,setup_time_utc,connect_time_utc,
		 disconnect_time_utc,source_timezone,source_utc_offset_minutes,time_source)`,
		func(batch driver.Batch) error {
			for _, record := range records {
				revision := record.TimezoneRevision
				if revision == 0 {
					revision = 1
				}
				if err := batch.Append(
					record.DeviceID, revision, record.RecordID, now,
					firstMapValue(record.RawFields, "setup_time", "setup", "setup-time"),
					firstMapValue(record.RawFields, "connect_time", "connect", "connect-time"),
					firstMapValue(record.RawFields, "disconnect_time", "disconnect", "disconnect-time"),
					record.SetupTime, record.ConnectTime, record.DisconnectTime,
					record.SourceTimezone, record.SourceUTCOffsetMinutes, "cdr_wall_clock",
				); err != nil {
					return err
				}
			}
			return nil
		})
}

func firstMapValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func redactStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		if redact.SecretName(key) {
			result[key] = redact.Replacement
		} else {
			result[key] = redact.Text(value)
		}
	}
	return result
}

func ParseCDRWallClock(value string, location *time.Location) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05"} {
		parsed, err := time.ParseInLocation(layout, value, location)
		if err == nil {
			utc := parsed.UTC()
			return &utc, nil
		}
	}
	return nil, fmt.Errorf("unsupported timestamp %q", value)
}

func (c *Client) ReinterpretCDRTimes(
	ctx context.Context, deviceID uuid.UUID, timezone string,
) error {
	if _, err := time.LoadLocation(timezone); err != nil {
		return err
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	return c.Conn.Exec(ctx, `INSERT INTO collector.cdr_time_interpretations
		(record_id,device_id,interpreted_at,setup_time,connect_time,disconnect_time,
		 source_timezone,source_utc_offset_minutes)
		SELECT c.record_id,c.device_id,now64(6),
			if(c.raw_fields['setup_time']='',c.setup_time,
				parseDateTime64BestEffortOrNull(c.raw_fields['setup_time'],6,?)),
			if(c.raw_fields['connect_time']='',c.connect_time,
				parseDateTime64BestEffortOrNull(c.raw_fields['connect_time'],6,?)),
			if(c.raw_fields['disconnect_time']='',c.disconnect_time,
				parseDateTime64BestEffortOrNull(c.raw_fields['disconnect_time'],6,?)),
			?,
			if(c.raw_fields['setup_time']='',toInt16(0),toInt16(dateDiff('minute',
				parseDateTime64BestEffortOrNull(c.raw_fields['setup_time'],6,?),
				parseDateTime64BestEffortOrNull(c.raw_fields['setup_time'],6,'UTC'))))
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=? AND (
			t.record_id=toUUID('00000000-0000-0000-0000-000000000000')
			OR t.source_timezone!=?)`,
		timezone, timezone, timezone, timezone, timezone, deviceID, timezone)
}

func (c *Client) ListCalls(ctx context.Context, deviceID uuid.UUID, search string, limit uint64) ([]CallRow, error) {
	page, err := c.ListCallsPage(ctx, deviceID, search, limit, nil)
	return page.Items, err
}

func (c *Client) ListCallsPage(ctx context.Context, deviceID uuid.UUID, search string, limit uint64, cursor *CallCursor) (CallPage, error) {
	return c.ListCallsPageRange(ctx, deviceID, search, limit, cursor, nil)
}

func (c *Client) ListCallsPageRange(
	ctx context.Context, deviceID uuid.UUID, search string, limit uint64,
	cursor *CallCursor, timeRange *TimeRange,
) (CallPage, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return CallPage{}, err
	}
	defer release()
	if search != "" && timeRange == nil && !c.admittedAs(ctx, workload.Export) {
		return CallPage{}, ErrSearchRequiresRange
	}
	if limit == 0 || limit > 1000 {
		limit = 200
	}
	query := `SELECT c.record_id,
		coalesce(t.setup_time,c.setup_time),
		coalesce(t.connect_time,c.connect_time),
		coalesce(t.disconnect_time,c.disconnect_time),
		c.duration_ms,c.release_cause,c.release_info,c.release_side,
		ifNull(toString(c.incoming_ip),''),ifNull(toString(c.outgoing_ip),''),
		c.incoming_type,c.outgoing_type,c.incoming_description,c.outgoing_description,
		c.incoming_cgpn,c.outgoing_cgpn,c.incoming_cdpn,c.outgoing_cdpn,
		c.incoming_redirecting_number,c.outgoing_redirecting_number,
		c.incoming_numplan,c.outgoing_numplan,c.calling_nai,c.called_nai,
		c.incoming_e1_stream,c.incoming_e1_channel,c.outgoing_e1_stream,c.outgoing_e1_channel,
		c.incoming_sip_call_id,c.outgoing_sip_call_id,c.incoming_ss7_cic,c.outgoing_ss7_cic,
		c.radius_session_id,c.radius_session_id_normalized,c.global_callref,c.unique_tag,
		c.transfer_mark,c.rejecting_radius_server,c.sequence_number,c.boot_epoch,c.sequence,
		c.source_timezone,c.source_utc_offset_minutes,
		coalesce(t.setup_time,c.setup_time,c.ingested_at) AS sort_time
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=?`
	args := []any{deviceID}
	if timeRange != nil {
		query += ` AND coalesce(t.setup_time,c.setup_time,c.ingested_at)>=?
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)<?`
		args = append(args, timeRange.From, timeRange.To)
	}
	if search != "" {
		query += ` AND (positionCaseInsensitive(c.incoming_cgpn,?)>0 OR positionCaseInsensitive(c.outgoing_cgpn,?)>0
			OR positionCaseInsensitive(c.incoming_cdpn,?)>0 OR positionCaseInsensitive(c.outgoing_cdpn,?)>0
			OR positionCaseInsensitive(c.radius_session_id,?)>0 OR positionCaseInsensitive(c.unique_tag,?)>0
			OR positionCaseInsensitive(c.incoming_description,?)>0 OR positionCaseInsensitive(c.outgoing_description,?)>0)`
		for range 8 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (coalesce(t.setup_time,c.setup_time,c.ingested_at) < ?
			OR (coalesce(t.setup_time,c.setup_time,c.ingested_at) = ? AND c.record_id < ?))`
		args = append(args, cursor.SortTime, cursor.SortTime, cursor.RecordID)
	}
	query += ` ORDER BY sort_time DESC,c.record_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return CallPage{}, err
	}
	defer rows.Close()
	result := make([]CallRow, 0)
	for rows.Next() {
		var row CallRow
		if err := rows.Scan(
			&row.RecordID, &row.SetupTime, &row.ConnectTime, &row.DisconnectTime,
			&row.DurationMS, &row.ReleaseCause, &row.ReleaseInfo, &row.ReleaseSide,
			&row.IncomingIP, &row.OutgoingIP, &row.IncomingType, &row.OutgoingType,
			&row.IncomingDescription, &row.OutgoingDescription,
			&row.IncomingCgPN, &row.OutgoingCgPN, &row.IncomingCdPN, &row.OutgoingCdPN,
			&row.IncomingRedirectingNumber, &row.OutgoingRedirectingNumber,
			&row.IncomingNumplan, &row.OutgoingNumplan, &row.CallingNAI, &row.CalledNAI,
			&row.IncomingE1Stream, &row.IncomingE1Channel, &row.OutgoingE1Stream, &row.OutgoingE1Channel,
			&row.IncomingSIPCallID, &row.OutgoingSIPCallID, &row.IncomingSS7CIC, &row.OutgoingSS7CIC,
			&row.RadiusSessionID, &row.RadiusSessionIDNormalized, &row.GlobalCallref, &row.UniqueTag,
			&row.TransferMark, &row.RejectingRadiusServer, &row.SequenceNumber, &row.BootEpoch,
			&row.Sequence, &row.SourceTimezone, &row.SourceUTCOffsetMinutes, &row.SortTime,
		); err != nil {
			return CallPage{}, err
		}
		row.SetupTimeLocal = localRFC3339(row.SetupTime, row.SourceTimezone)
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

func (c *Client) Stats(ctx context.Context, deviceID uuid.UUID) (DeviceStats, error) {
	now := time.Now().UTC()
	return c.StatsRange(ctx, deviceID, TimeRange{From: now.Add(-24 * time.Hour), To: now})
}

func (c *Client) StatsRange(
	ctx context.Context, deviceID uuid.UUID, timeRange TimeRange,
) (DeviceStats, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return DeviceStats{}, err
	}
	defer release()
	var result DeviceStats
	err = c.Conn.QueryRow(ctx, `SELECT count(),countIf(release_cause IS NOT NULL AND release_cause!=16),
		ifNull(avg(duration_ms),0)
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=? AND coalesce(t.setup_time,c.setup_time,c.ingested_at)>=?
			AND coalesce(t.setup_time,c.setup_time,c.ingested_at)<?`,
		deviceID, timeRange.From, timeRange.To).
		Scan(&result.Calls24h, &result.FailedCalls24h, &result.AverageTalkMS)
	if err != nil {
		return DeviceStats{}, err
	}
	err = c.Conn.QueryRow(ctx, `SELECT count() FROM collector.syslog_messages FINAL
		WHERE device_id=? AND received_at>=? AND received_at<?`,
		deviceID, timeRange.From, timeRange.To).Scan(&result.SyslogMessages24h)
	return result, err
}

func (c *Client) PurgeDeviceData(ctx context.Context, deviceID uuid.UUID) error {
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	rows, err := c.Conn.Query(ctx, `SELECT name
		FROM system.tables
		WHERE database='collector'
		  AND name IN (
			SELECT DISTINCT table
			FROM system.columns
			WHERE database='collector' AND name='device_id'
		  )
		  AND engine LIKE '%MergeTree%'`)
	if err != nil {
		return err
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, table)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	priority := map[string]int{
		"syslog_messages": 100, "cdr_records": 101,
	}
	sort.Slice(tables, func(left, right int) bool {
		leftPriority, leftSet := priority[tables[left]]
		rightPriority, rightSet := priority[tables[right]]
		if !leftSet {
			leftPriority = 50
		}
		if !rightSet {
			rightPriority = 50
		}
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		return tables[left] < tables[right]
	})
	for _, table := range tables {
		if strings.ContainsAny(table, "`\x00") {
			return fmt.Errorf("unsafe ClickHouse table name %q", table)
		}
		query := fmt.Sprintf(
			"ALTER TABLE collector.`%s` DELETE WHERE device_id=? SETTINGS mutations_sync=1",
			table,
		)
		if err := c.Conn.Exec(ctx, query, deviceID); err != nil {
			return fmt.Errorf("purge ClickHouse table %s: %w", table, err)
		}
		var remaining uint64
		verify := fmt.Sprintf("SELECT count() FROM collector.`%s` WHERE device_id=?", table)
		if err := c.Conn.QueryRow(ctx, verify, deviceID).Scan(&remaining); err != nil {
			return err
		}
		if remaining != 0 {
			return fmt.Errorf("ClickHouse table %s still has %d device rows", table, remaining)
		}
	}
	return nil
}
