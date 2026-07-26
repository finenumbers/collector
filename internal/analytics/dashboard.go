package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type DashboardDevice struct {
	DeviceID            uuid.UUID  `json:"deviceId"`
	Calls               uint64     `json:"calls"`
	FailedCalls         uint64     `json:"failedCalls"`
	AverageTalkMS       float64    `json:"averageTalkMs"`
	Alarms              uint64     `json:"alarms"`
	Unknown             uint64     `json:"unknown"`
	Antifraud           uint64     `json:"antifraud"`
	AntifraudRejected   uint64     `json:"antifraudRejected"`
	AntifraudIncomplete uint64     `json:"antifraudIncomplete"`
	LatestSyslogAt      *time.Time `json:"latestSyslogAt"`
	LatestCDRAt         *time.Time `json:"latestCdrAt"`
	ActiveRevision      uint64     `json:"activeRevision"`
	ActiveTimezone      string     `json:"activeTimezone"`
	BuildingRevision    uint64     `json:"buildingRevision"`
	RevisionStatus      string     `json:"revisionStatus"`
	RevisionReason      string     `json:"revisionReason"`
}

type DashboardAnalytics struct {
	Devices     map[uuid.UUID]*DashboardDevice `json:"-"`
	Diagnostics []string                       `json:"diagnostics"`
}

func (c *Client) Dashboard(ctx context.Context, window time.Duration) DashboardAnalytics {
	result := DashboardAnalytics{Devices: make(map[uuid.UUID]*DashboardDevice)}
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

	rows, err = c.Conn.Query(ctx, `SELECT i.device_id,countIf(i.category='alarms'),
		countIf(i.category='unknown')
		FROM collector.syslog_interpretations AS i FINAL
		INNER JOIN collector.raw_syslog AS r
			ON r.device_id=i.device_id AND r.event_id=i.event_id
		WHERE i.parser_version=? AND r.received_at>=now()-toIntervalSecond(?)
		GROUP BY i.device_id`, SyslogParserVersion, seconds)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "syslog: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var alarms, unknown uint64
			if scanErr := rows.Scan(&id, &alarms, &unknown); scanErr != nil {
				result.Diagnostics = append(result.Diagnostics, "syslog: "+scanErr.Error())
				break
			}
			target := device(id)
			target.Alarms, target.Unknown = alarms, unknown
		}
		_ = rows.Close()
	}

	rows, err = c.Conn.Query(ctx, `SELECT device_id,max(received_at)
		FROM collector.raw_syslog
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

	rows, err = c.Conn.Query(ctx, `SELECT l.device_id,count(),
		countIf(l.decision IN ('reject','verification_reject')),
		countIf(l.completeness!='complete')
		FROM collector.antifraud_lifecycles AS l FINAL
		INNER JOIN (
			SELECT device_id,maxIf(revision,status='active') AS revision
			FROM collector.device_derived_revisions FINAL GROUP BY device_id
		) AS d ON d.device_id=l.device_id AND d.revision=l.timezone_revision
		WHERE l.is_antifraud=1 AND l.last_event_at>=now()-toIntervalSecond(?)
		GROUP BY l.device_id`, seconds)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "antifraud: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var total, rejected, incomplete uint64
			if scanErr := rows.Scan(&id, &total, &rejected, &incomplete); scanErr != nil {
				result.Diagnostics = append(result.Diagnostics, "antifraud: "+scanErr.Error())
				break
			}
			target := device(id)
			target.Antifraud, target.AntifraudRejected, target.AntifraudIncomplete =
				total, rejected, incomplete
		}
		_ = rows.Close()
	}

	rows, err = c.Conn.Query(ctx, `SELECT device_id,
		maxIf(revision,status='active'),maxIf(revision,status IN ('building','cutover','ready')),
		argMax(status,updated_at),
		argMaxIf(timezone,updated_at,status='active'),
		argMaxIf(reason,updated_at,status IN ('building','cutover','ready'))
		FROM collector.device_derived_revisions FINAL GROUP BY device_id`)
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, "revisions: "+err.Error())
	} else {
		for rows.Next() {
			var id uuid.UUID
			var active, building uint64
			var status string
			var activeTimezone, reason string
			if scanErr := rows.Scan(
				&id, &active, &building, &status, &activeTimezone, &reason,
			); scanErr != nil {
				result.Diagnostics = append(result.Diagnostics, "revisions: "+scanErr.Error())
				break
			}
			target := device(id)
			target.ActiveRevision, target.BuildingRevision, target.RevisionStatus =
				active, building, status
			target.ActiveTimezone, target.RevisionReason = activeTimezone, reason
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
