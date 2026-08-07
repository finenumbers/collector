package analytics

import (
	"context"

	"collector/internal/workload"

	"github.com/google/uuid"
)

type DeviceProjectionFreshness struct {
	DeviceID             uuid.UUID `json:"deviceId"`
	SyslogLagSeconds     int64     `json:"syslogLagSeconds"`
	AFCallLagSeconds     int64     `json:"afCallLagSeconds"`
	AFSyslogLagSeconds   int64     `json:"afSyslogLagSeconds"`
	HasAFSyslogTip       bool      `json:"hasAFSyslogTip"`
	ActivatedLagSeconds  int64     `json:"activatedLagSeconds"`
	AFAuthHeaders6h      uint64    `json:"afAuthHeaders6h"`
	XpgkHeaders6h        uint64    `json:"xpgkHeaders6h"`
	ClassificationGap    bool      `json:"classificationGap"`
	ProjectionLagSeconds int64     `json:"projectionLagSeconds"`
	ProjectionSLOMet     bool      `json:"projectionSloMet"`
}

func (c *Client) DeviceProjectionFreshness(
	ctx context.Context, deviceIDs []uuid.UUID,
) (map[uuid.UUID]DeviceProjectionFreshness, error) {
	result := make(map[uuid.UUID]DeviceProjectionFreshness, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return result, nil
	}
	ctx, release, err := c.queryContext(ctx, workload.Diagnostics)
	if err != nil {
		return nil, err
	}
	defer release()
	// Tips only — no 6h payload substring scans (those starved Diagnostics 10s/128MiB).
	// ClassificationGap stays false here; queue depth / failed jobs cover ops signal.
	for _, deviceID := range deviceIDs {
		item := DeviceProjectionFreshness{DeviceID: deviceID}
		if err := c.queryRow(ctx, `SELECT
			greatest(0, dateDiff('second', ifNull(
				(SELECT max(received_at) FROM collector.syslog_messages WHERE device_id=?),
				now64(6)), now64(6))),
			greatest(0, dateDiff('second', ifNull(
				(SELECT max(last_seen_at) FROM collector.custom_antifraud_calls_current WHERE device_id=?),
				toDateTime64('1970-01-01', 6)), now64(6))),
			greatest(0, dateDiff('second', ifNull(
				(SELECT max(activated_at) FROM collector.custom_projection_state WHERE device_id=?),
				toDateTime64('1970-01-01', 6)), now64(6)))`,
			deviceID, deviceID, deviceID,
		).Scan(
			&item.SyslogLagSeconds, &item.AFCallLagSeconds, &item.ActivatedLagSeconds,
		); err != nil {
			return nil, err
		}
		item.AFSyslogLagSeconds = 0
		item.HasAFSyslogTip = false
		item.ProjectionLagSeconds = item.ActivatedLagSeconds
		item.ClassificationGap = false
		item.ProjectionSLOMet = item.ActivatedLagSeconds <= ProjectionHealthSLOSeconds
		result[deviceID] = item
	}
	return result, nil
}
