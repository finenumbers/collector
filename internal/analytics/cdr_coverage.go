package analytics

import (
	"context"
	"encoding/json"
	"time"

	"collector/internal/reconciliation"
	"collector/internal/workload"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

type CoverageThresholds struct {
	ExpectedGrace   time.Duration
	LateThreshold   time.Duration
	MissingTerminal time.Duration
	RetryHorizon    time.Duration
}

func (t CoverageThresholds) normalized() CoverageThresholds {
	if t.ExpectedGrace <= 0 {
		t.ExpectedGrace = 5 * time.Minute
	}
	if t.LateThreshold <= 0 {
		// Match runtimesettings.Defaults / previous AF age-fallback (not ExpectedGrace).
		t.LateThreshold = 10 * time.Minute
	}
	if t.LateThreshold < t.ExpectedGrace {
		t.LateThreshold = t.ExpectedGrace
	}
	if t.MissingTerminal <= 0 {
		t.MissingTerminal = 30 * time.Minute
	}
	if t.MissingTerminal < t.LateThreshold {
		t.MissingTerminal = t.LateThreshold
	}
	if t.RetryHorizon <= 0 {
		t.RetryHorizon = 7 * 24 * time.Hour
	}
	return t
}

func (c *Client) InsertCDRBatchWithCoverage(
	ctx context.Context, records []CDRRecord, enabled bool, policyRevision uint64,
	thresholds CoverageThresholds,
) error {
	ctx, release, err := c.queryContext(ctx, workload.Ingest)
	if err != nil {
		return err
	}
	defer release()
	if err := c.InsertCDRBatch(ctx, records); err != nil {
		return err
	}
	if len(records) == 0 {
		return nil
	}
	thresholds = thresholds.normalized()
	now := time.Now().UTC()
	seq := uint64(now.UnixNano())
	dirty := make(map[dirtyCoverageBucket]struct{})
	if err := c.withBatch(ctx, `INSERT INTO collector.cdr_antifraud_coverage
		(device_id,event_month,cdr_id,policy_revision,reconciliation_version,projection_seq,
		state,expected_at,grace_expires_at,missing_terminal_at,retry_until,method,reason,
		matched_evidence_json,ambiguous,ambiguity_reason,updated_at,deleted)`,
		func(batch driver.Batch) error {
			for _, record := range records {
				eventTime := cdrEventTime(record)
				state, reason := "expected", "awaiting_custom_call"
				if !enabled {
					state, reason = "not_applicable", "device_disabled"
				}
				if err := batch.Append(
					record.DeviceID, monthDate(eventTime), record.RecordID, policyRevision,
					reconciliation.Version, seq, state, now, eventTime.Add(thresholds.ExpectedGrace),
					eventTime.Add(thresholds.MissingTerminal), eventTime.Add(thresholds.RetryHorizon),
					"none", reason, "{}", uint8(0), "", now, uint8(0),
				); err != nil {
					return err
				}
				if enabled {
					dirty[dirtyCoverageBucket{
						deviceID: record.DeviceID, bucket: eventTime.UTC().Truncate(time.Hour),
					}] = struct{}{}
				}
			}
			return nil
		}); err != nil {
		return err
	}
	if len(dirty) == 0 {
		return nil
	}
	return c.withBatch(ctx, `INSERT INTO collector.cdr_reconciliation_dirty_buckets
		(device_id,bucket_start,policy_revision,projection_seq,reason,enqueued_at,deleted)`,
		func(batch driver.Batch) error {
			for item := range dirty {
				if err := batch.Append(
					item.deviceID, item.bucket, policyRevision, seq, "cdr_arrival", now, uint8(0),
				); err != nil {
					return err
				}
			}
			return nil
		})
}

type dirtyCoverageBucket struct {
	deviceID uuid.UUID
	bucket   time.Time
}

func cdrEventTime(record CDRRecord) time.Time {
	for _, value := range []*time.Time{record.SetupTime, record.ConnectTime, record.DisconnectTime} {
		if value != nil {
			return value.UTC()
		}
	}
	return record.IngestedAt.UTC()
}

func monthDate(value time.Time) time.Time {
	return time.Date(value.Year(), value.Month(), 1, 0, 0, 0, 0, time.UTC)
}

func encodeEvidence(value map[string]string) string {
	content, _ := json.Marshal(value)
	return string(content)
}
