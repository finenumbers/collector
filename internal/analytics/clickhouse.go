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
	"time"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

type Client struct {
	Conn clickhouse.Conn
}

type SyslogEvent struct {
	EventID      uuid.UUID
	DeviceID     uuid.UUID
	ReceivedAt   time.Time
	SourceIP     net.IP
	SourcePort   uint16
	Payload      []byte
	PRI          *uint16
	Facility     *uint8
	Severity     *uint8
	HeaderFormat string
	ParseStatus  string
	Category     string
	EventTime    *time.Time
	Component    string
	Message      string
	Attributes   map[string]string
}

type EventRow struct {
	EventID    uuid.UUID         `json:"eventId"`
	ReceivedAt time.Time         `json:"receivedAt"`
	Category   string            `json:"category"`
	Component  string            `json:"component"`
	Message    string            `json:"message"`
	RawPayload string            `json:"rawPayload"`
	Status     string            `json:"parseStatus"`
	Attributes map[string]string `json:"attributes"`
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
	Calls24h       uint64  `json:"calls24h"`
	FailedCalls24h uint64  `json:"failedCalls24h"`
	AverageTalkMS  float64 `json:"averageTalkMs"`
	Alarms24h      uint64  `json:"alarms24h"`
	Radius24h      uint64  `json:"radius24h"`
	Unknown24h     uint64  `json:"unknown24h"`
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
	IncomingSIPCallID, OutgoingSIPCallID       string
	IncomingSS7CIC, OutgoingSS7CIC             *uint32
	RadiusSessionID, RadiusSessionIDNormalized string
	GlobalCallref, UniqueTag, TransferMark     string
	RejectingRadiusServer                      string
	RawFields                                  map[string]string
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
	return &Client{Conn: conn}, nil
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
		 component,message,attributes)`)
	if err != nil {
		return err
	}
	for _, event := range events {
		sum := sha256.Sum256(event.Payload)
		if err := batch.Append(
			event.EventID, event.DeviceID, event.ReceivedAt, event.SourceIP, event.SourcePort, "udp",
			string(event.Payload), hex.EncodeToString(sum[:]), event.PRI, event.Facility, event.Severity,
			event.HeaderFormat, "smg-3.410-v3", event.ParseStatus, event.Category, event.EventTime,
			event.Component, event.Message, event.Attributes,
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
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.cdr_records`)
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
			record.IncomingCdPN, record.OutgoingCdPN, record.IncomingSIPCallID,
			record.OutgoingSIPCallID, record.IncomingSS7CIC, record.OutgoingSS7CIC,
			record.RadiusSessionID, record.RadiusSessionIDNormalized, record.GlobalCallref,
			record.UniqueTag, record.TransferMark, record.RejectingRadiusServer, record.RawFields,
		); err != nil {
			return err
		}
	}
	if err := batch.Send(); err != nil {
		return err
	}
	for _, record := range records {
		if record.RadiusSessionIDNormalized == "" {
			continue
		}
		if err := c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
			SELECT device_id,?,event_id,'exact_acct_session',toFloat32(1.0),
				map('acct_session_id',acct_session_id_normalized),'smg-3.410-v1',now64(3)
			FROM collector.radius_events
			WHERE device_id=? AND acct_session_id_normalized=?`,
			record.RecordID, record.DeviceID, record.RadiusSessionIDNormalized); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) InsertRadiusAndCorrelate(ctx context.Context, event SyslogEvent) error {
	sessionID := event.Attributes["acct_session_id"]
	normalized := strings.ToLower(strings.Join(strings.Fields(sessionID), ""))
	if normalized == "" {
		return nil
	}
	message := strings.ToLower(event.Message)
	packetCode := "unknown"
	result := ""
	for _, candidate := range []string{"access-request", "access-accept", "access-reject", "accounting-request", "accounting-response"} {
		if strings.Contains(message, candidate) {
			packetCode = candidate
			break
		}
	}
	switch {
	case strings.Contains(message, "access-accept"):
		result = "accept"
	case strings.Contains(message, "access-reject"):
		result = "reject"
	case strings.Contains(message, "timeout"):
		result = "timeout"
	}
	requestType := event.Attributes["xpgk_request_type"]
	occurredAt := event.ReceivedAt
	if event.EventTime != nil {
		occurredAt = *event.EventTime
	}
	if err := c.Conn.Exec(ctx, `INSERT INTO collector.radius_events
		(event_id,device_id,occurred_at,direction,packet_code,packet_identifier,request_type,
		 server_address,acct_session_id,acct_session_id_normalized,calling_station_id,
		 called_station_id,result,retry,latency_ms,attributes,raw_event_id)
		VALUES(?,?,?,'unknown',?,NULL,?,'',?,?,?,?,?,0,NULL,?,?)`,
		event.EventID, event.DeviceID, occurredAt, packetCode, requestType, sessionID, normalized,
		event.Attributes["calling_station_id"], event.Attributes["called_station_id"], result,
		event.Attributes, event.EventID); err != nil {
		return err
	}
	return c.Conn.Exec(ctx, `INSERT INTO collector.call_event_links
		SELECT device_id,record_id,?,'exact_acct_session',toFloat32(1.0),
			map('acct_session_id',radius_session_id_normalized),'smg-3.410-v1',now64(3)
		FROM collector.cdr_records
		WHERE device_id=? AND radius_session_id_normalized=?`,
		event.EventID, event.DeviceID, normalized)
}

func (c *Client) ListEvents(ctx context.Context, deviceID uuid.UUID, category, search string, limit uint64) ([]EventRow, error) {
	page, err := c.ListEventsPage(ctx, deviceID, category, search, limit, nil)
	return page.Items, err
}

func (c *Client) ListEventsPage(ctx context.Context, deviceID uuid.UUID, category, search string, limit uint64, cursor *EventCursor) (EventPage, error) {
	if limit == 0 || limit > 50000 {
		limit = 200
	}
	query := `SELECT event_id,received_at,category,component,message,payload,parse_status,attributes
		FROM collector.raw_syslog WHERE device_id=?`
	args := []any{deviceID}
	if category != "" && category != "all" {
		switch category {
		case "unknown":
			query += ` AND (category='unknown' OR parse_status!='parsed')`
		case "antifraud":
			query += ` AND category='radius'`
		default:
			query += ` AND category=?`
			args = append(args, category)
		}
	}
	if search != "" {
		query += ` AND positionCaseInsensitive(payload, ?) > 0`
		args = append(args, search)
	}
	if cursor != nil {
		query += ` AND (received_at < ? OR (received_at = ? AND event_id < ?))`
		args = append(args, cursor.ReceivedAt, cursor.ReceivedAt, cursor.EventID)
	}
	query += ` ORDER BY received_at DESC,event_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	result := make([]EventRow, 0)
	for rows.Next() {
		var row EventRow
		if err := rows.Scan(&row.EventID, &row.ReceivedAt, &row.Category, &row.Component,
			&row.Message, &row.RawPayload, &row.Status, &row.Attributes); err != nil {
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
	query := `SELECT record_id,setup_time,duration_ms,release_cause,release_info,
		incoming_cgpn,outgoing_cgpn,incoming_cdpn,outgoing_cdpn,
		incoming_description,outgoing_description,radius_session_id,unique_tag,
		coalesce(setup_time,ingested_at) AS sort_time
		FROM collector.cdr_records WHERE device_id=?`
	args := []any{deviceID}
	if search != "" {
		query += ` AND (positionCaseInsensitive(incoming_cgpn,?)>0 OR positionCaseInsensitive(outgoing_cgpn,?)>0
			OR positionCaseInsensitive(incoming_cdpn,?)>0 OR positionCaseInsensitive(outgoing_cdpn,?)>0
			OR positionCaseInsensitive(radius_session_id,?)>0 OR positionCaseInsensitive(unique_tag,?)>0
			OR positionCaseInsensitive(incoming_description,?)>0 OR positionCaseInsensitive(outgoing_description,?)>0)`
		for range 8 {
			args = append(args, search)
		}
	}
	if cursor != nil {
		query += ` AND (coalesce(setup_time,ingested_at) < ?
			OR (coalesce(setup_time,ingested_at) = ? AND record_id < ?))`
		args = append(args, cursor.SortTime, cursor.SortTime, cursor.RecordID)
	}
	query += ` ORDER BY sort_time DESC,record_id DESC LIMIT ?`
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
	rows, err := c.Conn.Query(ctx, `SELECT e.event_id,e.received_at,e.category,e.component,e.message,
		e.payload,e.parse_status,e.attributes,l.method,l.confidence
		FROM collector.call_event_links l
		INNER JOIN collector.raw_syslog e ON e.device_id=l.device_id AND e.event_id=l.event_id
		WHERE l.device_id=? AND l.cdr_record_id=?
		ORDER BY e.received_at`, deviceID, recordID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]TimelineRow, 0)
	for rows.Next() {
		var row TimelineRow
		if err := rows.Scan(&row.EventID, &row.ReceivedAt, &row.Category, &row.Component,
			&row.Message, &row.RawPayload, &row.Status, &row.Attributes, &row.Method, &row.Confidence); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (c *Client) Stats(ctx context.Context, deviceID uuid.UUID) (DeviceStats, error) {
	var result DeviceStats
	err := c.Conn.QueryRow(ctx, `SELECT count(),countIf(release_cause IS NOT NULL AND release_cause!=16),
		ifNull(avg(duration_ms),0)
		FROM collector.cdr_records
		WHERE device_id=? AND coalesce(setup_time,ingested_at)>=now()-INTERVAL 24 HOUR`, deviceID).
		Scan(&result.Calls24h, &result.FailedCalls24h, &result.AverageTalkMS)
	if err != nil {
		return DeviceStats{}, err
	}
	err = c.Conn.QueryRow(ctx, `SELECT countIf(category='alarms'),countIf(category='radius'),
		countIf(category='unknown' OR parse_status!='parsed')
		FROM collector.raw_syslog WHERE device_id=? AND received_at>=now()-INTERVAL 24 HOUR`, deviceID).
		Scan(&result.Alarms24h, &result.Radius24h, &result.Unknown24h)
	return result, err
}
