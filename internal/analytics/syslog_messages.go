package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"collector/internal/redact"
	"collector/internal/workload"

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
	batch, err := c.Conn.PrepareBatch(ctx, `INSERT INTO collector.syslog_messages
		(event_id,device_id,received_at,source_ip,source_port,transport,payload,payload_sha256)`)
	if err != nil {
		return err
	}
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
	return batch.Send()
}

func (c *Client) ListSyslogMessagesPage(
	ctx context.Context, deviceID uuid.UUID, search string, limit uint64,
	cursor *SyslogMessageCursor, timeRange *TimeRange,
) (SyslogMessagePage, error) {
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		return SyslogMessagePage{}, err
	}
	defer release()
	if limit == 0 || limit > 1000 {
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
	if cursor != nil {
		query += ` AND (received_at<? OR (received_at=? AND event_id<?))`
		args = append(args, cursor.ReceivedAt, cursor.ReceivedAt, cursor.EventID)
	}
	query += ` ORDER BY received_at DESC,event_id DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return SyslogMessagePage{}, err
	}
	defer rows.Close()
	items := make([]SyslogMessageRow, 0, limit)
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
	return SyslogMessagePage{Items: items, HasMore: hasMore}, nil
}
