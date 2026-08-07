package analytics

import (
	"context"
	"fmt"
	"io"
	"time"

	"collector/internal/workload"

	"github.com/google/uuid"
)

// ExportSyslogPayloadsRaw streams raw syslog payloads for [from,to) into w,
// one payload per line, ascending by (received_at, event_id). No redact.
// Caller should hold ClickHouse heavy-lane; this admits Export workload.
func (c *Client) ExportSyslogPayloadsRaw(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time, w io.Writer,
) (int64, error) {
	ctx, release, err := c.queryContext(ctx, workload.Export)
	if err != nil {
		return 0, err
	}
	defer release()

	const pageSize = uint64(5000)
	var (
		written int64
		cursor  *SyslogMessageCursor
	)
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		rows, err := c.querySyslogPayloadPage(ctx, deviceID, from, to, cursor, pageSize)
		if err != nil {
			return written, err
		}
		if len(rows) == 0 {
			return written, nil
		}
		for _, row := range rows {
			n, err := w.Write(row.Payload)
			if err != nil {
				return written, err
			}
			written += int64(n)
			if _, err := w.Write([]byte{'\n'}); err != nil {
				return written, err
			}
			written++
			cursor = &SyslogMessageCursor{ReceivedAt: row.ReceivedAt, EventID: row.EventID}
		}
		if uint64(len(rows)) < pageSize {
			return written, nil
		}
	}
}

type rawSyslogPayload struct {
	ReceivedAt time.Time
	EventID    uuid.UUID
	Payload    []byte
}

func (c *Client) querySyslogPayloadPage(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time,
	after *SyslogMessageCursor, limit uint64,
) ([]rawSyslogPayload, error) {
	query := `SELECT event_id,received_at,payload
		FROM collector.syslog_messages
		WHERE device_id=? AND received_at>=? AND received_at<?`
	args := []any{deviceID, from.UTC(), to.UTC()}
	if after != nil {
		query += ` AND (received_at>? OR (received_at=? AND event_id>?))`
		args = append(args, after.ReceivedAt, after.ReceivedAt, after.EventID)
	}
	query += ` ORDER BY received_at ASC, event_id ASC LIMIT ?`
	args = append(args, limit)
	rows, err := c.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]rawSyslogPayload, 0, limit)
	for rows.Next() {
		var row rawSyslogPayload
		var payload string
		if err := rows.Scan(&row.EventID, &row.ReceivedAt, &payload); err != nil {
			return nil, err
		}
		row.Payload = []byte(payload)
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 && after == nil {
		// empty hour is valid
		return out, nil
	}
	if limit == 0 {
		return nil, fmt.Errorf("syslog archive page limit is zero")
	}
	return out, nil
}
