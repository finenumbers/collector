package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

const SyslogParserVersion = "smg-3.410-v6"

type Client struct {
	Conn            clickhouse.Conn
	antifraudMu     sync.Mutex
	antifraudShards [64]sync.Mutex
	antifraudActive map[uuid.UUID]*AntifraudTransaction
}

type SyslogEvent struct {
	EventID                uuid.UUID
	DeviceID               uuid.UUID
	ReceivedAt             time.Time
	SourceIP               net.IP
	SourcePort             uint16
	Payload                []byte
	PRI                    *uint16
	Facility               *uint8
	Severity               *uint8
	HeaderFormat           string
	ParseStatus            string
	Category               string
	EventTime              *time.Time
	Component              string
	Message                string
	Attributes             map[string]string
	SourceTimezone         string
	SourceUTCOffsetMinutes int16
	TimezoneRevision       uint64
}

type EventRow struct {
	EventID         uuid.UUID         `json:"eventId"`
	ReceivedAt      time.Time         `json:"receivedAt"`
	EventTime       *time.Time        `json:"eventTime"`
	Category        string            `json:"category"`
	Component       string            `json:"component"`
	Message         string            `json:"message"`
	RawPayload      string            `json:"rawPayload"`
	Status          string            `json:"parseStatus"`
	Attributes      map[string]string `json:"attributes"`
	SourceTimezone  string            `json:"sourceTimezone"`
	EventTimeLocal  string            `json:"eventTimeLocal"`
	ReceivedAtLocal string            `json:"receivedAtLocal"`
}

type EventCursor struct {
	ReceivedAt time.Time
	EventID    uuid.UUID
}

type EventPage struct {
	Items   []EventRow
	HasMore bool
}

type TimelineRow struct {
	EventRow
	Method     string  `json:"method"`
	Confidence float32 `json:"confidence"`
}

type DeviceStats struct {
	Calls24h               uint64  `json:"calls24h"`
	FailedCalls24h         uint64  `json:"failedCalls24h"`
	AverageTalkMS          float64 `json:"averageTalkMs"`
	Alarms24h              uint64  `json:"alarms24h"`
	Radius24h              uint64  `json:"radius24h"`
	Unknown24h             uint64  `json:"unknown24h"`
	Antifraud24h           uint64  `json:"antifraud24h"`
	AntifraudRejected24h   uint64  `json:"antifraudRejected24h"`
	AntifraudIncomplete24h uint64  `json:"antifraudIncomplete24h"`
	UnlinkedCalls24h       uint64  `json:"unlinkedCalls24h"`
}

type SyslogBreakdownRow struct {
	Category       string    `json:"category"`
	ParseStatus    string    `json:"parseStatus"`
	ParserVersion  string    `json:"parserVersion"`
	HeaderFormat   string    `json:"headerFormat"`
	SourcePort     uint16    `json:"sourcePort"`
	Count          uint64    `json:"count"`
	LastReceivedAt time.Time `json:"lastReceivedAt"`
}

type SyslogDiagnostics struct {
	Breakdown            []SyslogBreakdownRow `json:"breakdown"`
	AppliedMigrations    []string             `json:"appliedMigrations"`
	RawEvents24h         uint64               `json:"rawEvents24h"`
	Classified24h        uint64               `json:"classified24h"`
	ReprocessedCurrent   uint64               `json:"reprocessedCurrent"`
	ReprocessRemaining   uint64               `json:"reprocessRemaining"`
	AntifraudComplete    uint64               `json:"antifraudComplete"`
	AntifraudIncomplete  uint64               `json:"antifraudIncomplete"`
	AntifraudOrphan      uint64               `json:"antifraudOrphan"`
	CorrelationExact     uint64               `json:"correlationExact"`
	CorrelationComposite uint64               `json:"correlationComposite"`
	CorrelationAmbiguous uint64               `json:"correlationAmbiguous"`
	ActiveRevision       uint64               `json:"activeRevision"`
	BuildingRevision     uint64               `json:"buildingRevision"`
	RevisionTimezone     string               `json:"revisionTimezone"`
	RevisionStatus       string               `json:"revisionStatus"`
	ReplayProcessed      uint64               `json:"replayProcessed"`
	ReplayTotal          uint64               `json:"replayTotal"`
	CDRReplayProcessed   uint64               `json:"cdrReplayProcessed"`
	CDRReplayTotal       uint64               `json:"cdrReplayTotal"`
	MissingCDRTimes      uint64               `json:"missingCdrInterpretations"`
	RadiusRawFragments   uint64               `json:"radiusRawFragments"`
	LifecycleDerived     uint64               `json:"lifecycleDerived"`
	CorrelationTotal     uint64               `json:"correlationTotal"`
	CorrelationOrphan    uint64               `json:"correlationOrphan"`
	LatestRawAt          time.Time            `json:"latestRawAt"`
	LatestFactAt         time.Time            `json:"latestFactAt"`
	LatestLifecycleAt    time.Time            `json:"latestLifecycleAt"`
	LatestAssignmentAt   time.Time            `json:"latestAssignmentAt"`
	PendingDirtyBuckets  uint64               `json:"pendingDirtyBuckets"`
	OldestDirtyAt        time.Time            `json:"oldestDirtyAt"`
}

type CallRow struct {
	RecordID            uuid.UUID  `json:"recordId"`
	SetupTime           *time.Time `json:"setupTime"`
	DurationMS          *uint64    `json:"durationMs"`
	ReleaseCause        *uint16    `json:"releaseCause"`
	ReleaseInfo         string     `json:"releaseInfo"`
	IncomingCgPN        string     `json:"incomingCgpn"`
	OutgoingCgPN        string     `json:"outgoingCgpn"`
	IncomingCdPN        string     `json:"incomingCdpn"`
	OutgoingCdPN        string     `json:"outgoingCdpn"`
	IncomingDescription string     `json:"incomingDescription"`
	OutgoingDescription string     `json:"outgoingDescription"`
	RadiusSessionID     string     `json:"radiusSessionId"`
	UniqueTag           string     `json:"uniqueTag"`
	SetupTimeLocal      string     `json:"setupTimeLocal"`
	SourceTimezone      string     `json:"sourceTimezone"`
	SortTime            time.Time  `json:"-"`
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
		Addr:        []string{addr},
		Auth:        clickhouse.Auth{Database: database, Username: username, Password: password},
		DialTimeout: 10 * time.Second,
		Compression: &clickhouse.Compression{Method: clickhouse.CompressionLZ4},
	})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, err
	}
	return &Client{Conn: conn, antifraudActive: make(map[uuid.UUID]*AntifraudTransaction)}, nil
}

func (c *Client) Migrate(ctx context.Context, directory string) error {
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

func (c *Client) InsertSyslog(ctx context.Context, event SyslogEvent) error {
	return c.InsertSyslogBatch(ctx, []SyslogEvent{event})
}

func (c *Client) InsertSyslogBatch(ctx context.Context, events []SyslogEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.raw_syslog
		(event_id,device_id,received_at,source_ip,source_port,transport,payload,payload_sha256,
		 pri,facility,severity,header_format,parser_version,parse_status,category,event_time,
		 component,message,attributes,source_timezone,source_utc_offset_minutes)`)
	if err != nil {
		return err
	}
	for _, event := range events {
		sum := sha256.Sum256(event.Payload)
		if err := batch.Append(
			event.EventID, event.DeviceID, event.ReceivedAt, event.SourceIP, event.SourcePort, "udp",
			string(event.Payload), hex.EncodeToString(sum[:]), event.PRI, event.Facility, event.Severity,
			event.HeaderFormat, SyslogParserVersion, event.ParseStatus, event.Category, event.EventTime,
			event.Component, event.Message, event.Attributes, event.SourceTimezone,
			event.SourceUTCOffsetMinutes,
		); err != nil {
			return err
		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	return c.InsertSyslogInterpretationsBatch(ctx, events)
}

func (c *Client) InsertSyslogInterpretationsBatch(
	ctx context.Context, events []SyslogEvent,
) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_interpretations
		(event_id,device_id,interpreted_at,parser_version,parse_status,category,event_time,
		 component,message,attributes,source_timezone,source_utc_offset_minutes)`)
	if err != nil {
		return err
	}
	interpretedAt := time.Now().UTC()
	for _, event := range events {
		if err := batch.Append(
			event.EventID, event.DeviceID, interpretedAt, SyslogParserVersion,
			event.ParseStatus, event.Category, event.EventTime, event.Component,
			event.Message, event.Attributes, event.SourceTimezone,
			event.SourceUTCOffsetMinutes,
		); err != nil {
			return err
		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	return c.InsertSyslogFactsBatch(ctx, events)
}

func (c *Client) InsertSyslogFactsBatch(ctx context.Context, events []SyslogEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_facts
		(device_id,timezone_revision,event_id,interpreted_at,received_at,raw_wall_clock,
		 event_time_utc,source_timezone,source_utc_offset_minutes,parse_status,category,
		 component,message,attributes)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, event := range events {
		revision := event.TimezoneRevision
		if revision == 0 {
			revision = 1
		}
		rawWallClock := ""
		if event.EventTime != nil {
			location, locationErr := time.LoadLocation(event.SourceTimezone)
			if locationErr != nil {
				return fmt.Errorf("invalid Syslog source timezone %q: %w", event.SourceTimezone, locationErr)
			}
			rawWallClock = event.EventTime.In(location).Format("2006-01-02 15:04:05.999999")
		}
		if err := batch.Append(
			event.DeviceID, revision, event.EventID, now, event.ReceivedAt, rawWallClock,
			event.EventTime, event.SourceTimezone, event.SourceUTCOffsetMinutes,
			event.ParseStatus, event.Category, event.Component, event.Message, event.Attributes,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func (c *Client) InsertCDRBatch(ctx context.Context, records []CDRRecord) error {
	if len(records) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.cdr_records
		(record_id,device_id,file_id,row_number,ingested_at,sequence_number,boot_epoch,sequence,
		 setup_time,connect_time,disconnect_time,duration_ms,release_cause,release_info,
		 release_side,incoming_ip,outgoing_ip,incoming_type,outgoing_type,incoming_description,
		 outgoing_description,incoming_cgpn,outgoing_cgpn,incoming_cdpn,outgoing_cdpn,
		 incoming_redirecting_number,outgoing_redirecting_number,incoming_numplan,outgoing_numplan,
		 calling_nai,called_nai,incoming_e1_stream,incoming_e1_channel,outgoing_e1_stream,
		 outgoing_e1_channel,incoming_sip_call_id,outgoing_sip_call_id,incoming_ss7_cic,
		 outgoing_ss7_cic,radius_session_id,radius_session_id_normalized,global_callref,
		 unique_tag,transfer_mark,rejecting_radius_server,raw_fields,source_timezone,
		 source_utc_offset_minutes)`)
	if err != nil {
		return err
	}
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
			record.UniqueTag, record.TransferMark, record.RejectingRadiusServer, record.RawFields,
			record.SourceTimezone, record.SourceUTCOffsetMinutes,
		); err != nil {
			return err
		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	if err := c.InsertCDRTimeInterpretationsBatch(ctx, records); err != nil {
		return err
	}
	return c.EnqueueDirtyCDRBuckets(ctx, records)
}

func (c *Client) InsertCDRTimeInterpretationsBatch(
	ctx context.Context, records []CDRRecord,
) error {
	if len(records) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.cdr_time_interpretations
		(record_id,device_id,interpreted_at,setup_time,connect_time,disconnect_time,
		 source_timezone,source_utc_offset_minutes)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, record := range records {
		if err := batch.Append(
			record.RecordID, record.DeviceID, now, record.SetupTime, record.ConnectTime,
			record.DisconnectTime, record.SourceTimezone, record.SourceUTCOffsetMinutes,
		); err != nil {
			return err
		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	return c.InsertCDRTimeFactsBatch(ctx, records)
}

func (c *Client) InsertCDRTimeFactsBatch(ctx context.Context, records []CDRRecord) error {
	if len(records) == 0 {
		return nil
	}
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.cdr_time_facts
		(device_id,timezone_revision,record_id,interpreted_at,setup_wall_clock,
		 connect_wall_clock,disconnect_wall_clock,setup_time_utc,connect_time_utc,
		 disconnect_time_utc,source_timezone,source_utc_offset_minutes)`)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
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
			record.SourceTimezone, record.SourceUTCOffsetMinutes,
		); err != nil {
			return err
		}
	}
	return batch.Send()
}

func firstMapValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func (c *Client) ReinterpretCDRTimes(
	ctx context.Context, deviceID uuid.UUID, timezone string,
) error {
	if _, err := time.LoadLocation(timezone); err != nil {
		return err
	}
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

func (c *Client) ListEvents(ctx context.Context, deviceID uuid.UUID, category, search string, limit uint64) ([]EventRow, error) {
	page, err := c.ListEventsPage(ctx, deviceID, category, search, limit, nil)
	return page.Items, err
}

func (c *Client) ListEventsPage(ctx context.Context, deviceID uuid.UUID, category, search string, limit uint64, cursor *EventCursor) (EventPage, error) {
	if limit == 0 || limit > 50000 {
		limit = 200
	}
	if revision, err := c.ActiveDeviceRevision(ctx, deviceID); err != nil {
		return EventPage{}, err
	} else if revision != 0 {
		return c.listCurrentEventsPage(ctx, deviceID, revision, category, search, limit, cursor)
	} else {
		return c.listFallbackEventsPage(ctx, deviceID, category, search, limit, cursor)
	}
	query := `SELECT r.event_id,r.received_at,i.event_time,i.category,i.component,i.message,
		r.payload,i.parse_status,i.attributes,i.source_timezone
		FROM collector.syslog_interpretations AS i FINAL
		INNER JOIN collector.raw_syslog r
			ON r.device_id=i.device_id AND r.event_id=i.event_id
		WHERE i.device_id=? AND i.parser_version=?`
	args := []any{deviceID, SyslogParserVersion}
	if category != "" && category != "all" {
		switch category {
		case "unknown":
			query += ` AND i.category='unknown'`
		default:
			query += ` AND i.category=?`
			args = append(args, category)
		}
	}
	if search != "" {
		query += ` AND positionCaseInsensitive(r.payload, ?) > 0`
		args = append(args, search)
	}
	if cursor != nil {
		query += ` AND (r.received_at < ? OR (r.received_at = ? AND r.event_id < ?))`
		args = append(args, cursor.ReceivedAt, cursor.ReceivedAt, cursor.EventID)
	}
	query += ` ORDER BY r.received_at DESC,r.event_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	result := make([]EventRow, 0)
	for rows.Next() {
		var row EventRow
		if err := rows.Scan(&row.EventID, &row.ReceivedAt, &row.EventTime,
			&row.Category, &row.Component, &row.Message, &row.RawPayload,
			&row.Status, &row.Attributes, &row.SourceTimezone); err != nil {
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

func (c *Client) ListCalls(ctx context.Context, deviceID uuid.UUID, search string, limit uint64) ([]CallRow, error) {
	page, err := c.ListCallsPage(ctx, deviceID, search, limit, nil)
	return page.Items, err
}

func (c *Client) ListCallsPage(ctx context.Context, deviceID uuid.UUID, search string, limit uint64, cursor *CallCursor) (CallPage, error) {
	if limit == 0 || limit > 50000 {
		limit = 200
	}
	if revision, err := c.ActiveDeviceRevision(ctx, deviceID); err != nil {
		return CallPage{}, err
	} else if revision != 0 {
		return c.listCurrentCallsPage(ctx, deviceID, revision, search, limit, cursor)
	}
	query := `SELECT c.record_id,coalesce(t.setup_time,c.setup_time),c.duration_ms,
		c.release_cause,c.release_info,c.incoming_cgpn,c.outgoing_cgpn,c.incoming_cdpn,
		c.outgoing_cdpn,c.incoming_description,c.outgoing_description,c.radius_session_id,
		c.unique_tag,coalesce(t.setup_time,c.setup_time,c.ingested_at) AS sort_time
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=?`
	args := []any{deviceID}
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
		if err := rows.Scan(&row.RecordID, &row.SetupTime, &row.DurationMS, &row.ReleaseCause,
			&row.ReleaseInfo, &row.IncomingCgPN, &row.OutgoingCgPN, &row.IncomingCdPN,
			&row.OutgoingCdPN, &row.IncomingDescription, &row.OutgoingDescription,
			&row.RadiusSessionID, &row.UniqueTag, &row.SortTime); err != nil {
			return CallPage{}, err
		}
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

func (c *Client) CallTimeline(ctx context.Context, deviceID, recordID uuid.UUID) ([]TimelineRow, error) {
	if revision, err := c.ActiveDeviceRevision(ctx, deviceID); err != nil {
		return nil, err
	} else if revision != 0 {
		return c.currentCallTimeline(ctx, deviceID, revision, recordID)
	}
	rows, err := c.Conn.Query(ctx, `SELECT e.event_id,e.received_at,i.event_time,i.category,
		i.component,i.message,e.payload,i.parse_status,i.attributes,i.source_timezone,
		l.method,l.max_confidence
		FROM (
			SELECT device_id,event_id,argMax(method,confidence) AS method,
				max(confidence) AS max_confidence
			FROM collector.call_event_links
			WHERE device_id=? AND cdr_record_id=? AND parser_version=?
			GROUP BY device_id,event_id
		) l
		INNER JOIN collector.raw_syslog e ON e.device_id=l.device_id AND e.event_id=l.event_id
		INNER JOIN collector.syslog_interpretations AS i FINAL
			ON i.device_id=e.device_id AND i.event_id=e.event_id
		WHERE i.parser_version=?
		ORDER BY e.received_at`, deviceID, recordID, SyslogParserVersion,
		SyslogParserVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TimelineRow, 0)
	for rows.Next() {
		var row TimelineRow
		if err := rows.Scan(&row.EventID, &row.ReceivedAt, &row.EventTime,
			&row.Category, &row.Component, &row.Message, &row.RawPayload,
			&row.Status, &row.Attributes, &row.SourceTimezone,
			&row.Method, &row.Confidence); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (c *Client) Stats(ctx context.Context, deviceID uuid.UUID) (DeviceStats, error) {
	if revision, err := c.ActiveDeviceRevision(ctx, deviceID); err != nil {
		return DeviceStats{}, err
	} else if revision != 0 {
		return c.currentStats(ctx, deviceID, revision)
	}
	var result DeviceStats
	err := c.Conn.QueryRow(ctx, `SELECT count(),countIf(release_cause IS NOT NULL AND release_cause!=16),
		ifNull(avg(duration_ms),0)
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		WHERE c.device_id=? AND coalesce(t.setup_time,c.setup_time,c.ingested_at)>=now()-INTERVAL 24 HOUR`,
		deviceID).
		Scan(&result.Calls24h, &result.FailedCalls24h, &result.AverageTalkMS)
	if err != nil {
		return DeviceStats{}, err
	}
	err = c.Conn.QueryRow(ctx, `SELECT countIf(i.category='alarms'),countIf(i.category='radius'),
		countIf(i.category='unknown')
		FROM collector.syslog_interpretations AS i FINAL
		INNER JOIN collector.raw_syslog r ON r.device_id=i.device_id AND r.event_id=i.event_id
		WHERE i.device_id=? AND i.parser_version=?
			AND r.received_at>=now()-INTERVAL 24 HOUR`, deviceID, SyslogParserVersion).
		Scan(&result.Alarms24h, &result.Radius24h, &result.Unknown24h)
	if err != nil {
		return DeviceStats{}, err
	}
	err = c.Conn.QueryRow(ctx, `SELECT count(),countIf(decision='reject'),
		countIf(completeness!='complete')
		FROM collector.antifraud_transactions FINAL
		WHERE device_id=? AND is_antifraud=1
			AND last_event_at>=now()-INTERVAL 24 HOUR`,
		deviceID).
		Scan(&result.Antifraud24h, &result.AntifraudRejected24h,
			&result.AntifraudIncomplete24h)
	if err != nil {
		return DeviceStats{}, err
	}
	err = c.Conn.QueryRow(ctx, `SELECT count()
		FROM collector.cdr_records AS c FINAL
		LEFT JOIN collector.cdr_time_interpretations AS t FINAL
			ON t.device_id=c.device_id AND t.record_id=c.record_id
		LEFT JOIN (
			SELECT DISTINCT device_id,cdr_record_id
			FROM collector.call_event_links
			WHERE parser_version=?
		) l ON l.device_id=c.device_id AND l.cdr_record_id=c.record_id
		WHERE c.device_id=? AND coalesce(t.setup_time,c.setup_time,c.ingested_at)>=now()-INTERVAL 24 HOUR
			AND l.cdr_record_id=toUUID('00000000-0000-0000-0000-000000000000')`,
		SyslogParserVersion, deviceID).
		Scan(&result.UnlinkedCalls24h)
	return result, err
}

func (c *Client) SyslogDiagnostics(ctx context.Context, deviceID uuid.UUID) (SyslogDiagnostics, error) {
	if revision, err := c.ActiveDeviceRevision(ctx, deviceID); err != nil {
		return SyslogDiagnostics{}, err
	} else if revision != 0 {
		return c.currentDiagnostics(ctx, deviceID, revision)
	}
	rows, err := c.Conn.Query(ctx, `SELECT i.category,i.parse_status,i.parser_version,
		r.header_format,r.source_port,count(),max(r.max_received_at)
		FROM collector.syslog_interpretations AS i FINAL
		INNER JOIN (
			SELECT event_id,device_id,any(header_format) AS header_format,
				any(source_port) AS source_port,max(received_at) AS max_received_at
			FROM collector.raw_syslog
			WHERE device_id=? AND received_at>=now()-INTERVAL 24 HOUR
			GROUP BY event_id,device_id
		) r ON r.device_id=i.device_id AND r.event_id=i.event_id
		WHERE i.device_id=? AND i.parser_version=?
		GROUP BY i.category,i.parse_status,i.parser_version,r.header_format,r.source_port
		ORDER BY count() DESC`, deviceID, deviceID, SyslogParserVersion)
	if err != nil {
		return SyslogDiagnostics{}, err
	}
	defer rows.Close()
	result := SyslogDiagnostics{Breakdown: make([]SyslogBreakdownRow, 0)}
	for rows.Next() {
		var item SyslogBreakdownRow
		if err := rows.Scan(&item.Category, &item.ParseStatus, &item.ParserVersion,
			&item.HeaderFormat, &item.SourcePort, &item.Count, &item.LastReceivedAt); err != nil {
			return SyslogDiagnostics{}, err
		}
		result.Breakdown = append(result.Breakdown, item)
	}
	if err := rows.Err(); err != nil {
		return SyslogDiagnostics{}, err
	}
	migrationRows, err := c.Conn.Query(ctx,
		`SELECT version FROM collector.schema_migrations FINAL ORDER BY version`)
	if err != nil {
		return SyslogDiagnostics{}, err
	}
	defer migrationRows.Close()
	result.AppliedMigrations = make([]string, 0)
	for migrationRows.Next() {
		var version string
		if err := migrationRows.Scan(&version); err != nil {
			return SyslogDiagnostics{}, err
		}
		result.AppliedMigrations = append(result.AppliedMigrations, version)
	}
	if err := migrationRows.Err(); err != nil {
		return SyslogDiagnostics{}, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT
		(SELECT countDistinct(event_id) FROM collector.raw_syslog
		 WHERE device_id=? AND received_at>=now()-INTERVAL 24 HOUR),
		(SELECT countDistinct(i.event_id)
		 FROM collector.syslog_interpretations AS i FINAL
		 INNER JOIN collector.raw_syslog r ON r.event_id=i.event_id AND r.device_id=i.device_id
		 WHERE i.device_id=? AND i.parser_version=? AND i.category!='unknown'
			AND r.received_at>=now()-INTERVAL 24 HOUR)`,
		deviceID, deviceID, SyslogParserVersion).
		Scan(&result.RawEvents24h, &result.Classified24h); err != nil {
		return SyslogDiagnostics{}, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT
		(SELECT countDistinct(r.event_id)
		 FROM collector.raw_syslog r
		 INNER JOIN collector.syslog_reprocess_ledger l ON l.event_id=r.event_id
		 WHERE r.device_id=? AND l.parser_version=?),
		(SELECT countDistinct(r.event_id)
		 FROM collector.raw_syslog r
		 LEFT JOIN collector.syslog_reprocess_ledger l
			ON l.event_id=r.event_id AND l.parser_version=?
		 WHERE r.device_id=?
			AND l.event_id=toUUID('00000000-0000-0000-0000-000000000000'))`,
		deviceID, SyslogParserVersion, SyslogParserVersion, deviceID).
		Scan(&result.ReprocessedCurrent, &result.ReprocessRemaining); err != nil {
		return SyslogDiagnostics{}, err
	}
	if err := c.Conn.QueryRow(ctx, `SELECT countIf(completeness='complete'),
		countIf(completeness!='complete'),
		countIf(transaction_id NOT IN (
			SELECT transaction_id FROM collector.antifraud_call_links
			WHERE device_id=? AND ambiguity=0
		))
		FROM collector.antifraud_transactions FINAL
		WHERE device_id=? AND is_antifraud=1`,
		deviceID, deviceID).
		Scan(&result.AntifraudComplete, &result.AntifraudIncomplete,
			&result.AntifraudOrphan); err != nil {
		return SyslogDiagnostics{}, err
	}
	_ = c.Conn.QueryRow(ctx, `SELECT exact_linked,composite_linked,ambiguous
		FROM collector.correlation_runs FINAL
		WHERE device_id=? AND parser_version=? ORDER BY ran_at DESC LIMIT 1`,
		deviceID, SyslogParserVersion).
		Scan(&result.CorrelationExact, &result.CorrelationComposite,
			&result.CorrelationAmbiguous)
	_ = c.Conn.QueryRow(ctx, `SELECT revision,timezone,status,processed,raw_total,
		cdr_processed,cdr_total
		FROM collector.device_derived_revisions FINAL
		WHERE device_id=? AND status IN ('building','cutover')
		ORDER BY revision DESC LIMIT 1`, deviceID).
		Scan(&result.BuildingRevision, &result.RevisionTimezone, &result.RevisionStatus,
			&result.ReplayProcessed, &result.ReplayTotal, &result.CDRReplayProcessed,
			&result.CDRReplayTotal)
	return result, nil
}

func (c *Client) InvalidateDeviceDerivedData(ctx context.Context, deviceID uuid.UUID) error {
	mutations := []string{
		`ALTER TABLE collector.syslog_reprocess_ledger DELETE
			WHERE device_id=? AND parser_version=? SETTINGS mutations_sync=1`,
		`ALTER TABLE collector.syslog_interpretations DELETE
			WHERE device_id=? AND parser_version=? SETTINGS mutations_sync=1`,
		`ALTER TABLE collector.radius_events DELETE
			WHERE device_id=? AND parser_version=? SETTINGS mutations_sync=1`,
		`ALTER TABLE collector.antifraud_transactions DELETE
			WHERE device_id=? AND parser_version=? SETTINGS mutations_sync=1`,
		`ALTER TABLE collector.call_event_links DELETE
			WHERE device_id=? AND parser_version=? SETTINGS mutations_sync=1`,
		`ALTER TABLE collector.antifraud_call_links DELETE
			WHERE device_id=? AND parser_version=? SETTINGS mutations_sync=1`,
		`ALTER TABLE collector.correlation_runs DELETE
			WHERE device_id=? AND parser_version=? SETTINGS mutations_sync=1`,
	}
	for _, mutation := range mutations {
		if err := c.Conn.Exec(ctx, mutation, deviceID, SyslogParserVersion); err != nil {
			return err
		}
	}
	c.antifraudMu.Lock()
	for transactionID, transaction := range c.antifraudActive {
		if transaction.DeviceID == deviceID {
			delete(c.antifraudActive, transactionID)
		}
	}
	c.antifraudMu.Unlock()
	return nil
}
