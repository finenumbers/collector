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
				toDateTime64('1970-01-01', 6)), now64(6))),
			(SELECT countIf(positionCaseInsensitiveUTF8(payload,'Antifraud-Auth-Request')>0)
				FROM collector.syslog_messages
				WHERE device_id=? AND received_at>=now()-INTERVAL 6 HOUR),
			(SELECT countIf(positionCaseInsensitiveUTF8(payload,'xpgk-request-type')>0)
				FROM collector.syslog_messages
				WHERE device_id=? AND received_at>=now()-INTERVAL 6 HOUR)`,
			deviceID, deviceID, deviceID, deviceID, deviceID,
		).Scan(
			&item.SyslogLagSeconds, &item.AFCallLagSeconds, &item.ActivatedLagSeconds,
			&item.AFAuthHeaders6h, &item.XpgkHeaders6h,
		); err != nil {
			return nil, err
		}
		item.ProjectionLagSeconds = item.ActivatedLagSeconds
		item.ClassificationGap = item.SyslogLagSeconds <= 300 &&
			item.AFAuthHeaders6h == 0 && item.XpgkHeaders6h == 0 &&
			item.AFCallLagSeconds >= 900
		// CH-only freshness cannot see queue depth; final SLO is computed in
		// httpapi diagnostics via EvaluateProjectionDeviceHealth.
		item.ProjectionSLOMet = !item.ClassificationGap &&
			item.ActivatedLagSeconds <= ProjectionHealthSLOSeconds
		result[deviceID] = item
	}
	return result, nil
}
