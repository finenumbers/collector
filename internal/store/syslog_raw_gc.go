package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type SyslogRawGC struct {
	DeviceID     uuid.UUID
	HourStartUTC time.Time
	SealedAt     *time.Time
	RawDeletedAt *time.Time
	LastError    string
}

func (s *Store) SealSyslogUTCHour(ctx context.Context, deviceID uuid.UUID, hourStart time.Time) error {
	hour := hourStart.UTC().Truncate(time.Hour)
	_, err := s.DB.Exec(ctx, `
		INSERT INTO syslog_raw_gc (device_id, hour_start_utc, sealed_at, updated_at)
		VALUES ($1,$2,now(),now())
		ON CONFLICT (device_id, hour_start_utc) DO UPDATE SET
			sealed_at=COALESCE(syslog_raw_gc.sealed_at, now()),
			updated_at=now()`,
		deviceID, hour)
	return err
}

func (s *Store) MarkSyslogRawDeleted(ctx context.Context, deviceID uuid.UUID, hourStart time.Time) error {
	hour := hourStart.UTC().Truncate(time.Hour)
	_, err := s.DB.Exec(ctx, `
		INSERT INTO syslog_raw_gc (device_id, hour_start_utc, sealed_at, raw_deleted_at, last_error, updated_at)
		VALUES ($1,$2,now(),now(),'',now())
		ON CONFLICT (device_id, hour_start_utc) DO UPDATE SET
			sealed_at=COALESCE(syslog_raw_gc.sealed_at, now()),
			raw_deleted_at=now(), last_error='', updated_at=now()`,
		deviceID, hour)
	return err
}

func (s *Store) FailSyslogRawGC(ctx context.Context, deviceID uuid.UUID, hourStart time.Time, message string) error {
	hour := hourStart.UTC().Truncate(time.Hour)
	_, err := s.DB.Exec(ctx, `
		INSERT INTO syslog_raw_gc (device_id, hour_start_utc, last_error, updated_at)
		VALUES ($1,$2,$3,now())
		ON CONFLICT (device_id, hour_start_utc) DO UPDATE SET
			last_error=$3, updated_at=now()`,
		deviceID, hour, message)
	return err
}

func (s *Store) SyslogRawAlreadyDeleted(ctx context.Context, deviceID uuid.UUID, hourStart time.Time) (bool, error) {
	var done bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM syslog_raw_gc
		WHERE device_id=$1 AND hour_start_utc=$2 AND raw_deleted_at IS NOT NULL
	)`, deviceID, hourStart.UTC().Truncate(time.Hour)).Scan(&done)
	return done, err
}

func (s *Store) CustomProjectionHourCompleted(
	ctx context.Context, deviceID uuid.UUID, hourStart time.Time,
) (completed bool, enabled bool, err error) {
	policy, err := s.CustomAntifraudPolicy(ctx, deviceID)
	if err != nil {
		return false, false, err
	}
	if !policy.Enabled {
		return true, false, nil
	}
	hour := hourStart.UTC().Truncate(time.Hour)
	var status string
	queryErr := s.DB.QueryRow(ctx, `
		SELECT status FROM custom_projection_jobs
		WHERE device_id=$1 AND kind='bucket' AND bucket_start=$2
		LIMIT 1`, deviceID, hour).Scan(&status)
	if queryErr == nil {
		return status == "completed", true, nil
	}
	if queryErr != nil && !errors.Is(queryErr, pgx.ErrNoRows) {
		return false, true, queryErr
	}
	var watermark *time.Time
	var state string
	err = s.DB.QueryRow(ctx, `
		SELECT watermark_received_at, state FROM custom_projection_watermarks
		WHERE device_id=$1 AND policy_revision=$2`,
		deviceID, policy.Revision).Scan(&watermark, &state)
	if err != nil {
		return false, true, nil
	}
	if state == "disabled" {
		return true, false, nil
	}
	if watermark != nil && !watermark.Before(hour.Add(time.Hour)) {
		return true, true, nil
	}
	return false, true, nil
}

func (s *Store) ListSyslogCapableDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+deviceSelectColumns+`
		FROM devices
		WHERE enabled AND purge_state='active'
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Device
	for rows.Next() {
		var device Device
		if err := scanDeviceRow(rows, &device); err != nil {
			return nil, err
		}
		normalizeDeviceFirmware(&device)
		if !device.Capabilities.Syslog {
			continue
		}
		result = append(result, device)
	}
	return result, rows.Err()
}
