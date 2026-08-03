package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"collector/internal/redact"
	"collector/internal/workload"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

var ErrSearchRequiresRange = errors.New("search requires a device date range")

const maxSyslogPayloadResponseBytes = 16 << 10

// SyslogMessage is the immutable transport record. Future parsers consume this
// model and persist their own projections without changing raw collection.
type SyslogMessage struct {
	EventID    uuid.UUID
	DeviceID   uuid.UUID
	ReceivedAt time.Time
	SourceIP   net.IP
	SourcePort uint16
	Transport  string
	Payload    []byte
}

type SyslogMessageRow struct {
	EventID       uuid.UUID `json:"eventId"`
	DeviceID      uuid.UUID `json:"deviceId"`
	ReceivedAt    time.Time `json:"receivedAt"`
	SourceIP      string    `json:"sourceIp"`
	SourcePort    uint16    `json:"sourcePort"`
	Transport     string    `json:"transport"`
	Payload       string    `json:"payload"`
	PayloadSHA256 string    `json:"payloadSha256"`
	Truncated     bool      `json:"truncated,omitempty"`
}

type SyslogMessageCursor struct {
	ReceivedAt time.Time
	EventID    uuid.UUID
}

type SyslogMessagePage struct {
	Items   []SyslogMessageRow `json:"items"`
	HasMore bool               `json:"hasMore"`
}

func (c *Client) InsertSyslogMessagesBatch(
	ctx context.Context, messages []SyslogMessage,
) error {
	if len(messages) == 0 {
		return nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Ingest)
	if err != nil {
		return err
	}
	defer release()
	return c.withBatch(ctx, `INSERT INTO collector.syslog_messages
		(event_id,device_id,received_at,source_ip,source_port,transport,payload,payload_sha256)`,
		func(batch driver.Batch) error {
			for _, message := range messages {
				sum := sha256.Sum256(message.Payload)
				transport := message.Transport
				if transport == "" {
					transport = "udp"
				}
				if err := batch.Append(
					message.EventID, message.DeviceID, message.ReceivedAt, message.SourceIP,
					message.SourcePort, transport, string(message.Payload), hex.EncodeToString(sum[:]),
				); err != nil {
					return err
				}
			}
			return nil
		})
}

// SyslogListBound selects keyset pagination mode. At most one of Before/From/After.
type SyslogListBound struct {
	// Before: exclusive older-than cursor (default infinite scroll down).
	Before *SyslogMessageCursor
	// From: inclusive start — first row is this event, then older.
	From *SyslogMessageCursor
	// After: exclusive newer-than — fetch newer rows (ASC), return DESC.
	After *SyslogMessageCursor
}

func (c *Client) ListSyslogMessagesPage(
	ctx context.Context, deviceID uuid.UUID, search string, limit uint64,
	cursor *SyslogMessageCursor, timeRange *TimeRange,
) (SyslogMessagePage, error) {
	return c.ListSyslogMessagesBound(ctx, deviceID, search, limit, SyslogListBound{Before: cursor}, timeRange)
}

func (c *Client) ListSyslogMessagesBound(
	ctx context.Context, deviceID uuid.UUID, search string, limit uint64,
	bound SyslogListBound, timeRange *TimeRange,
) (SyslogMessagePage, error) {
	modes := 0
	if bound.Before != nil {
		modes++
	}
	if bound.From != nil {
		modes++
	}
	if bound.After != nil {
		modes++
	}
	if modes > 1 {
		return SyslogMessagePage{}, errors.New("conflicting syslog list cursors")
	}
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return SyslogMessagePage{}, err
	}
	defer release()
	const maxPage = 1000
	if limit == 0 || limit > maxPage {
		limit = 200
	}
	if search != "" && timeRange == nil && !c.admittedAs(ctx, workload.Export) {
		return SyslogMessagePage{}, ErrSearchRequiresRange
	}
	query := `SELECT event_id,device_id,received_at,toString(source_ip),source_port,
		transport,payload,payload_sha256
		FROM collector.syslog_messages FINAL WHERE device_id=?`
	args := []any{deviceID}
	if timeRange != nil {
		query += ` AND received_at>=? AND received_at<?`
		args = append(args, timeRange.From, timeRange.To)
	}
	if search != "" {
		query += ` AND positionCaseInsensitiveUTF8(payload,?)>0`
		args = append(args, search)
	}
	newer := bound.After != nil
	switch {
	case bound.Before != nil:
		query += ` AND (received_at<? OR (received_at=? AND event_id<?))`
		args = append(args, bound.Before.ReceivedAt, bound.Before.ReceivedAt, bound.Before.EventID)
	case bound.From != nil:
		query += ` AND (received_at<? OR (received_at=? AND event_id<=?))`
		args = append(args, bound.From.ReceivedAt, bound.From.ReceivedAt, bound.From.EventID)
	case bound.After != nil:
		query += ` AND (received_at>? OR (received_at=? AND event_id>?))`
		args = append(args, bound.After.ReceivedAt, bound.After.ReceivedAt, bound.After.EventID)
	}
	if newer {
		query += ` ORDER BY received_at ASC,event_id ASC LIMIT ?`
	} else {
		query += ` ORDER BY received_at DESC,event_id DESC LIMIT ?`
	}
	args = append(args, limit+1)
	rows, err := c.query(ctx, query, args...)
	if err != nil {
		return SyslogMessagePage{}, err
	}
	defer rows.Close()
	items := make([]SyslogMessageRow, 0, maxPage+1)
	for rows.Next() {
		var row SyslogMessageRow
		if err := rows.Scan(
			&row.EventID, &row.DeviceID, &row.ReceivedAt, &row.SourceIP, &row.SourcePort,
			&row.Transport, &row.Payload, &row.PayloadSHA256,
		); err != nil {
			return SyslogMessagePage{}, err
		}
		row.Payload = redact.Text(row.Payload)
		if len(row.Payload) > maxSyslogPayloadResponseBytes {
			row.Payload = row.Payload[:maxSyslogPayloadResponseBytes]
			row.Truncated = true
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return SyslogMessagePage{}, err
	}
	hasMore := uint64(len(items)) > limit
	if hasMore {
		items = items[:limit]
	}
	if newer {
		for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
			items[left], items[right] = items[right], items[left]
		}
	}
	return SyslogMessagePage{Items: items, HasMore: hasMore}, nil
}

// SyslogFindResult is one payload match within a device day, newest-first.
type SyslogFindResult struct {
	EventID    uuid.UUID
	ReceivedAt time.Time
	Found      bool
	HasMore    bool
}

func (c *Client) FindSyslogMessage(
	ctx context.Context, deviceID uuid.UUID, search string,
	cursor *SyslogMessageCursor, timeRange *TimeRange,
) (SyslogFindResult, error) {
	search = strings.TrimSpace(search)
	if search == "" {
		return SyslogFindResult{}, ErrSearchRequiresRange
	}
	if timeRange == nil && !c.admittedAs(ctx, workload.Export) {
		return SyslogFindResult{}, ErrSearchRequiresRange
	}
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return SyslogFindResult{}, err
	}
	defer release()
	query := `SELECT event_id,received_at
		FROM collector.syslog_messages FINAL WHERE device_id=?`
	args := []any{deviceID}
	if timeRange != nil {
		query += ` AND received_at>=? AND received_at<?`
		args = append(args, timeRange.From, timeRange.To)
	}
	query += ` AND positionCaseInsensitiveUTF8(payload,?)>0`
	args = append(args, search)
	if cursor != nil {
		query += ` AND (received_at<? OR (received_at=? AND event_id<?))`
		args = append(args, cursor.ReceivedAt, cursor.ReceivedAt, cursor.EventID)
	}
	query += ` ORDER BY received_at DESC,event_id DESC LIMIT 2`
	rows, err := c.query(ctx, query, args...)
	if err != nil {
		return SyslogFindResult{}, err
	}
	defer rows.Close()
	var result SyslogFindResult
	for rows.Next() {
		var eventID uuid.UUID
		var receivedAt time.Time
		if err := rows.Scan(&eventID, &receivedAt); err != nil {
			return SyslogFindResult{}, err
		}
		if !result.Found {
			result.EventID = eventID
			result.ReceivedAt = receivedAt
			result.Found = true
			continue
		}
		result.HasMore = true
		break
	}
	if err := rows.Err(); err != nil {
		return SyslogFindResult{}, err
	}
	return result, nil
}

func (c *Client) CountSyslogMessages(
	ctx context.Context, deviceID uuid.UUID, search string, timeRange *TimeRange,
) (uint64, error) {
	search = strings.TrimSpace(search)
	if search == "" || (timeRange == nil && !c.admittedAs(ctx, workload.Export)) {
		return 0, ErrSearchRequiresRange
	}
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return 0, err
	}
	defer release()
	query := `SELECT count()
		FROM collector.syslog_messages FINAL WHERE device_id=?`
	args := []any{deviceID}
	if timeRange != nil {
		query += ` AND received_at>=? AND received_at<?`
		args = append(args, timeRange.From, timeRange.To)
	}
	query += ` AND positionCaseInsensitiveUTF8(payload,?)>0`
	args = append(args, search)
	var total uint64
	if err := c.queryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}
