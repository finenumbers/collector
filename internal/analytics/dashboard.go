package analytics

import (
	"context"
	"fmt"
	"time"

	"collector/internal/redact"
	"collector/internal/workload"

	"github.com/google/uuid"
)

type DashboardDevice struct {
	DeviceID                   uuid.UUID  `json:"deviceId"`
	Calls                      uint64     `json:"calls"`
	FailedCalls                uint64     `json:"failedCalls"`
	AverageTalkMS              float64    `json:"averageTalkMs"`
	Antifraud                  uint64     `json:"antifraud"`
	AntifraudRejected          uint64     `json:"antifraudRejected"`
	AntifraudIncomplete        uint64     `json:"antifraudIncomplete"`
	VoipmonitorMatchedExact    uint64     `json:"voipmonitorMatchedExact"`
	VoipmonitorMatchedFallback uint64     `json:"voipmonitorMatchedFallback"`
	VoipmonitorAmbiguous       uint64     `json:"voipmonitorAmbiguous"`
	VoipmonitorUnmatched       uint64     `json:"voipmonitorUnmatched"`
	LatestSyslogAt             *time.Time `json:"latestSyslogAt"`
	LatestCDRAt                *time.Time `json:"latestCdrAt"`
	ActiveRevision             uint64     `json:"activeRevision"`
	ActiveTimezone             string     `json:"activeTimezone"`
	BuildingRevision           uint64     `json:"buildingRevision"`
	RevisionStatus             string     `json:"revisionStatus"`
	RevisionReason             string     `json:"revisionReason"`
}

type DashboardAnalytics struct {
	Devices     map[uuid.UUID]*DashboardDevice `json:"-"`
	Diagnostics []string                       `json:"diagnostics"`
}

func (c *Client) Dashboard(ctx context.Context, window time.Duration) DashboardAnalytics {
	result := DashboardAnalytics{Devices: make(map[uuid.UUID]*DashboardDevice)}
	ctx, release, err := c.queryContext(ctx, workload.Interactive)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, redact.Text(err.Error()))
		return result
	}
	defer release()
	seconds := uint64(window / time.Second)
	device := func(id uuid.UUID) *DashboardDevice {
		if result.Devices[id] == nil {
			result.Devices[id] = &DashboardDevice{DeviceID: id}
		}
		return result.Devices[id]
	}

	rows, err := c.Conn.Query(ctx, `SELECT device_id,count(),
		countIf(release_cause IS NOT NULL AND release_cause!=16),
		ifNull(avg(duration_ms),0),max(ingested_at)
		FROM collector.cdr_records FINAL
		WHERE ingested_at>=now()-toIntervalSecond(?)
		GROUP BY device_id`, seconds)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "cdr: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var latest time.Time
			item := DashboardDevice{}
			if scanErr := rows.Scan(&id, &item.Calls, &item.FailedCalls,
				&item.AverageTalkMS, &latest); scanErr != nil {
				result.Diagnostics = append(result.Diagnostics, "cdr: "+scanErr.Error())
				break
			}
			target := device(id)
			target.Calls, target.FailedCalls, target.AverageTalkMS =
				item.Calls, item.FailedCalls, item.AverageTalkMS
			target.LatestCDRAt = &latest
		}
		if closeErr := rows.Close(); closeErr != nil {
			result.Diagnostics = append(result.Diagnostics, "cdr: "+closeErr.Error())
		}
	}

	rows, err = c.Conn.Query(ctx, `SELECT device_id,count(),countIf(outcome!='answered'),
		ifNull(avgIf(duration_ms,outcome='answered'),0),max(ingested_at)
		FROM collector.satel_rtu_cdr FINAL
		WHERE ingested_at>=now()-toIntervalSecond(?)
		GROUP BY device_id`, seconds)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "satel_rtu_cdr: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var latest time.Time
			item := DashboardDevice{}
			if scanErr := rows.Scan(&id, &item.Calls, &item.FailedCalls,
				&item.AverageTalkMS, &latest); scanErr != nil {
				result.Diagnostics = append(result.Diagnostics, "satel_rtu_cdr: "+scanErr.Error())
				break
			}
			target := device(id)
			target.Calls += item.Calls
			target.FailedCalls += item.FailedCalls
			if target.Calls == item.Calls {
				target.AverageTalkMS = item.AverageTalkMS
			}
			target.LatestCDRAt = &latest
		}
		if closeErr := rows.Close(); closeErr != nil {
			result.Diagnostics = append(result.Diagnostics, "satel_rtu_cdr: "+closeErr.Error())
		}
	}

	rows, err = c.Conn.Query(ctx, `SELECT device_id,max(received_at)
		FROM collector.syslog_messages FINAL
		WHERE received_at>=now()-toIntervalSecond(?)
		GROUP BY device_id`, seconds)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "raw syslog freshness: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var latest time.Time
			if scanErr := rows.Scan(&id, &latest); scanErr != nil {
				result.Diagnostics = append(
					result.Diagnostics, "raw syslog freshness: "+scanErr.Error(),
				)
				break
			}
			device(id).LatestSyslogAt = &latest
		}
		_ = rows.Close()
	}

	rows, err = c.Conn.Query(ctx, `SELECT device_id,count(),countIf(status='blocked'),
		countIf(status IN ('unavailable_fallback','ambiguous_indeterminate','pending','open'))
		FROM collector.custom_antifraud_calls_current
		WHERE first_seen_at>=now()-toIntervalSecond(?)
		GROUP BY device_id`, seconds)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "custom antifraud calls: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var total, rejected, incomplete uint64
			if scanErr := rows.Scan(&id, &total, &rejected, &incomplete); scanErr != nil {
				result.Diagnostics = append(
					result.Diagnostics, "custom antifraud calls: "+scanErr.Error(),
				)
				break
			}
			target := device(id)
			target.Antifraud = total
			target.AntifraudRejected = rejected
			target.AntifraudIncomplete = incomplete
		}
		_ = rows.Close()
	}

	rows, err = c.Conn.Query(ctx, `
		SELECT device_id,
			countIf(match_status='matched_exact'),
			countIf(match_status='matched_fallback'),
			countIf(match_status='ambiguous'),
			countIf(match_status='unmatched')
		FROM
		(
			SELECT c.device_id AS device_id, link.match_status AS match_status
			FROM collector.cdr_records AS c FINAL
			INNER JOIN collector.cdr_voipmonitor_links_current AS link
				ON link.device_id=c.device_id
				AND link.source_record_id=c.record_id
				AND link.source_system='eltex_smg'
			WHERE c.ingested_at>=now()-toIntervalSecond(?)
			UNION ALL
			SELECT c.device_id AS device_id, link.match_status AS match_status
			FROM collector.satel_rtu_cdr AS c FINAL
			INNER JOIN collector.cdr_voipmonitor_links_current AS link
				ON link.device_id=c.device_id
				AND link.source_record_id=c.record_id
				AND link.source_system='satel_rtu'
			WHERE c.ingested_at>=now()-toIntervalSecond(?)
		)
		GROUP BY device_id`, seconds, seconds)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "voipmonitor links: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var exact, fallback, ambiguous, unmatched uint64
			if scanErr := rows.Scan(&id, &exact, &fallback, &ambiguous, &unmatched); scanErr != nil {
				result.Diagnostics = append(
					result.Diagnostics, "voipmonitor links: "+scanErr.Error(),
				)
				break
			}
			target := device(id)
			target.VoipmonitorMatchedExact = exact
			target.VoipmonitorMatchedFallback = fallback
			target.VoipmonitorAmbiguous = ambiguous
			target.VoipmonitorUnmatched = unmatched
		}
		_ = rows.Close()
	}

	if result.Diagnostics == nil {
		result.Diagnostics = []string{}
	}
	return result
}

func ValidateDashboardWindow(value string) (time.Duration, error) {
	if value == "" {
		value = "24h"
	}
	switch value {
	case "1h", "24h", "7d":
	default:
		return 0, fmt.Errorf("window must be one of 1h, 24h, or 7d")
	}
	if value == "7d" {
		return 7 * 24 * time.Hour, nil
	}
	return time.ParseDuration(value)
}
