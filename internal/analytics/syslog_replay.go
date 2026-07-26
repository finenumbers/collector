package analytics

import (
	"context"
	"fmt"
	"net"

	clickhouse "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
)

const deviceSyslogReplayQuery = `SELECT
	event_id,device_id,received_at,toUnixTimestamp64Micro(received_at),
	source_ip,source_port,payload,source_timezone
	FROM collector.raw_syslog
	WHERE device_id=?
	  AND tuple(toUnixTimestamp64Micro(received_at),event_id)>tuple(?,?)
	  AND tuple(toUnixTimestamp64Micro(received_at),event_id)<=tuple(?,?)
	ORDER BY received_at,event_id
	LIMIT 1 BY event_id
	LIMIT ?`

type SyslogReplayWatermark struct {
	ReceivedAtUS int64
	EventID      uuid.UUID
	TotalEvents  uint64
}

type SyslogReplayQueryOptions struct {
	MaxThreads     int
	MaxMemoryUsage uint64
	QueryLabel     string
}

func (c *Client) DeviceSyslogReplayWatermark(
	ctx context.Context, deviceID uuid.UUID, options SyslogReplayQueryOptions,
) (SyslogReplayWatermark, error) {
	var watermark SyslogReplayWatermark
	countContext := syslogReplayQueryContext(ctx, deviceID, options)
	if err := c.Conn.QueryRow(countContext, `SELECT count()
		FROM collector.raw_syslog WHERE device_id=?`, deviceID).
		Scan(&watermark.TotalEvents); err != nil || watermark.TotalEvents == 0 {
		return watermark, err
	}
	watermarkContext := syslogReplayQueryContext(ctx, deviceID, options)
	err := c.Conn.QueryRow(watermarkContext, `SELECT
		toUnixTimestamp64Micro(received_at),event_id
		FROM collector.raw_syslog
		WHERE device_id=?
		ORDER BY received_at DESC,event_id DESC
		LIMIT 1`, deviceID).Scan(&watermark.ReceivedAtUS, &watermark.EventID)
	return watermark, err
}

func (c *Client) NextDeviceSyslogReplayBatch(
	ctx context.Context,
	deviceID uuid.UUID,
	cursorReceivedUS int64,
	cursorEventID uuid.UUID,
	watermarkReceivedUS int64,
	watermarkEventID uuid.UUID,
	limit uint64,
	options SyslogReplayQueryOptions,
) ([]ReplaySyslogRow, error) {
	if limit == 0 {
		return nil, nil
	}
	ctx = syslogReplayQueryContext(ctx, deviceID, options)
	rows, err := c.Conn.Query(ctx, deviceSyslogReplayQuery,
		deviceID, cursorReceivedUS, cursorEventID,
		watermarkReceivedUS, watermarkEventID, limit)
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
			&item.EventID, &item.DeviceID, &item.ReceivedAt, &item.ReceivedAtUS,
			&sourceIP, &item.SourcePort, &payload, &item.SourceTimezone,
		); err != nil {
			return nil, err
		}
		item.SourceIP = sourceIP
		item.Payload = []byte(payload)
		result = append(result, item)
	}
	return result, rows.Err()
}

func syslogReplayQueryContext(
	ctx context.Context, deviceID uuid.UUID, options SyslogReplayQueryOptions,
) context.Context {
	if options.MaxThreads <= 0 {
		options.MaxThreads = 2
	}
	if options.MaxMemoryUsage == 0 {
		options.MaxMemoryUsage = 512 << 20
	}
	label := options.QueryLabel
	if label == "" {
		label = "syslog-parser-rebuild"
	}
	queryID := fmt.Sprintf("%s/%s/%s", label, deviceID, uuid.NewString())
	return clickhouse.Context(ctx,
		clickhouse.WithQueryID(queryID),
		clickhouse.WithSettings(clickhouse.Settings{
			"max_threads":      options.MaxThreads,
			"max_memory_usage": options.MaxMemoryUsage,
		}),
	)
}
