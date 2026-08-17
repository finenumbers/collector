package analytics

import (
	"context"
	"fmt"
	"time"

	"collector/internal/workload"

	"github.com/google/uuid"
)

const SyslogMessagesBufferTTLHours = 72

type SyslogSlotFingerprint struct {
	Count         int64
	MaxReceivedAt time.Time
	MaxEventID    uuid.UUID
}

func (c *Client) SyslogSlotFingerprint(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time,
) (SyslogSlotFingerprint, error) {
	ctx, release, err := c.queryContext(ctx, workload.CustomReconcile)
	if err != nil {
		return SyslogSlotFingerprint{}, err
	}
	defer release()
	var fp SyslogSlotFingerprint
	var count uint64
	var maxAt time.Time
	var maxID uuid.UUID
	err = c.queryRow(ctx, `SELECT count(), max(received_at), argMax(event_id, (received_at, event_id))
		FROM collector.syslog_messages
		WHERE device_id=? AND received_at>=? AND received_at<?`,
		deviceID, from.UTC(), to.UTC()).Scan(&count, &maxAt, &maxID)
	if err != nil {
		return SyslogSlotFingerprint{}, err
	}
	fp.Count = int64(count)
	if fp.Count > 0 {
		fp.MaxReceivedAt = maxAt.UTC()
		fp.MaxEventID = maxID
	}
	return fp, nil
}

func (c *Client) ClickHouseBusyForMutation(ctx context.Context) error {
	var mutations, merges uint64
	if err := c.queryRow(ctx, `SELECT
		(SELECT count() FROM system.mutations WHERE database='collector' AND NOT is_done),
		(SELECT count() FROM system.merges WHERE database='collector')`).
		Scan(&mutations, &merges); err != nil {
		return fmt.Errorf("read ClickHouse merge pressure: %w", err)
	}
	if mutations > 16 || merges > 32 {
		return fmt.Errorf(
			"ClickHouse is busy (%d active mutations, %d merges); deferred",
			mutations, merges,
		)
	}
	return nil
}

func (c *Client) DeleteSyslogRange(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time,
) error {
	if err := c.ClickHouseBusyForMutation(ctx); err != nil {
		return err
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	if err := c.exec(ctx, `ALTER TABLE collector.syslog_messages
		DELETE WHERE device_id=? AND received_at>=? AND received_at<?
		SETTINGS mutations_sync=1`, deviceID, from.UTC(), to.UTC()); err != nil {
		return err
	}
	var remaining uint64
	if err := c.queryRow(ctx, `SELECT count() FROM collector.syslog_messages
		WHERE device_id=? AND received_at>=? AND received_at<?`,
		deviceID, from.UTC(), to.UTC()).Scan(&remaining); err != nil {
		return err
	}
	if remaining != 0 {
		return fmt.Errorf("syslog_messages still has %d rows in deleted hour", remaining)
	}
	return nil
}

func (c *Client) DeleteSyslogOlderThan(ctx context.Context, cutoff time.Time) error {
	if err := c.ClickHouseBusyForMutation(ctx); err != nil {
		return err
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	return c.exec(ctx, `ALTER TABLE collector.syslog_messages
		DELETE WHERE received_at<? SETTINGS mutations_sync=1`, cutoff.UTC())
}

func (c *Client) ApplySyslogMessagesBufferTTL(ctx context.Context) error {
	if err := c.ClickHouseBusyForMutation(ctx); err != nil {
		return err
	}
	ctx, release, err := c.queryContext(ctx, workload.CustomReplay)
	if err != nil {
		return err
	}
	defer release()
	return c.exec(ctx, fmt.Sprintf(
		`ALTER TABLE collector.syslog_messages
		 MODIFY TTL toDateTime(received_at) + INTERVAL %d HOUR DELETE`,
		SyslogMessagesBufferTTLHours,
	))
}

func (c *Client) PendingAntiFraudCoverage(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time,
) (uint64, error) {
	ctx, release, err := c.queryContext(ctx, workload.CustomReconcile)
	if err != nil {
		return 0, err
	}
	defer release()
	var count uint64
	err = c.queryRow(ctx, `SELECT count()
		FROM collector.cdr_antifraud_coverage_current
		WHERE device_id=? AND expected_at>=? AND expected_at<?
		  AND state IN ('expected','late')`,
		deviceID, from.UTC(), to.UTC()).Scan(&count)
	return count, err
}
