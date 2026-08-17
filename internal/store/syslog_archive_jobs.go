package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	SyslogArchiveStatusPending      = "pending"
	SyslogArchiveStatusBuilding     = "building"
	SyslogArchiveStatusReady        = "ready"
	SyslogArchiveStatusUploading    = "uploading"
	SyslogArchiveStatusUploaded     = "uploaded"
	SyslogArchiveStatusFailed       = "failed"
	SyslogArchiveStatusAbandoned    = "abandoned"
	SyslogArchiveStatusSkippedStale = "skipped_stale"

	syslogArchiveOrchestratorLockKey int64 = 0x53594C4152434831 // SYLARCH1
	DefaultSyslogArchiveLease              = 2 * time.Minute
	syslogRawGCLockKey               int64 = 0x53594C5241574731 // SYLRAWG1
)

type SyslogArchiveJob struct {
	ID            uuid.UUID  `json:"id"`
	DeviceID      uuid.UUID  `json:"deviceId"`
	HourStart     time.Time  `json:"hourStart"`
	ArchiveName   string     `json:"archiveName"`
	RemoteDir     string     `json:"remoteDir"`
	Timezone      string     `json:"timezone"`
	Status        string     `json:"status"`
	LocalPath     string     `json:"localPath"`
	Bytes         int64      `json:"bytes"`
	PayloadCount  int64      `json:"payloadCount"`
	MaxReceivedAt *time.Time `json:"maxReceivedAt,omitempty"`
	MaxEventID    *uuid.UUID `json:"maxEventId,omitempty"`
	Attempts      int        `json:"attempts"`
	LastError     string     `json:"lastError"`
	NextAttemptAt time.Time  `json:"nextAttemptAt"`
	WorkerID      string     `json:"workerId,omitempty"`
	HeartbeatAt   *time.Time `json:"heartbeatAt,omitempty"`
	LeaseExpires  *time.Time `json:"leaseExpiresAt,omitempty"`
	UploadedAt    *time.Time `json:"uploadedAt,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

const syslogArchiveJobColumns = `id,device_id,hour_start,archive_name,remote_dir,timezone,status,
	local_path,bytes,payload_count,max_received_at,max_event_id,attempts,last_error,next_attempt_at,
	COALESCE(worker_id,''),heartbeat_at,lease_expires_at,uploaded_at,created_at,updated_at`

func scanSyslogArchiveJob(row pgx.Row) (SyslogArchiveJob, error) {
	var job SyslogArchiveJob
	err := row.Scan(
		&job.ID, &job.DeviceID, &job.HourStart, &job.ArchiveName, &job.RemoteDir, &job.Timezone,
		&job.Status, &job.LocalPath, &job.Bytes, &job.PayloadCount, &job.MaxReceivedAt, &job.MaxEventID,
		&job.Attempts, &job.LastError, &job.NextAttemptAt,
		&job.WorkerID, &job.HeartbeatAt, &job.LeaseExpires, &job.UploadedAt, &job.CreatedAt, &job.UpdatedAt,
	)
	return job, err
}

func (s *Store) TrySyslogArchiveOrchestratorLock(ctx context.Context) (func(), bool, error) {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, syslogArchiveOrchestratorLockKey).
		Scan(&acquired); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !acquired {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, syslogArchiveOrchestratorLockKey)
		conn.Release()
	}, true, nil
}

func (s *Store) EnsureSyslogArchiveJob(
	ctx context.Context, deviceID uuid.UUID, hourStart time.Time,
	archiveName, remoteDir, timezone string,
) (SyslogArchiveJob, error) {
	blocked, err := s.SyslogUTCHourBlocked(ctx, deviceID, hourStart.UTC().Truncate(time.Hour))
	if err != nil {
		return SyslogArchiveJob{}, err
	}
	if blocked {
		return SyslogArchiveJob{}, ErrNotFound
	}
	id := uuid.New()
	job, err := scanSyslogArchiveJob(s.DB.QueryRow(ctx, `
		INSERT INTO syslog_archive_jobs
			(id,device_id,hour_start,archive_name,remote_dir,timezone,status)
		VALUES ($1,$2,$3,$4,$5,$6,'pending')
		ON CONFLICT (device_id, hour_start) DO UPDATE SET
			updated_at=syslog_archive_jobs.updated_at
		RETURNING `+syslogArchiveJobColumns,
		id, deviceID, hourStart.UTC(), archiveName, remoteDir, timezone,
	))
	return job, err
}

func (s *Store) EnsureSyslogArchiveSkippedStale(
	ctx context.Context, deviceID uuid.UUID, hourStart time.Time,
	archiveName, remoteDir, timezone string,
) error {
	_, err := s.DB.Exec(ctx, `
		INSERT INTO syslog_archive_jobs
			(id,device_id,hour_start,archive_name,remote_dir,timezone,status,last_error)
		VALUES ($1,$2,$3,$4,$5,$6,'skipped_stale','outside lookback')
		ON CONFLICT (device_id, hour_start) DO NOTHING`,
		uuid.New(), deviceID, hourStart.UTC(), archiveName, remoteDir, timezone,
	)
	return err
}

// ClaimSyslogArchiveJob prefers ready/failed upload work, then pending builds.
// When allowBuild is false, only upload-phase jobs are claimed.
func (s *Store) ClaimSyslogArchiveJob(
	ctx context.Context, workerID string, lease time.Duration, allowBuild bool,
) (SyslogArchiveJob, error) {
	if lease <= 0 {
		lease = DefaultSyslogArchiveLease
	}
	secs := int(lease.Seconds())
	job, err := scanSyslogArchiveJob(s.DB.QueryRow(ctx, `
		WITH candidate AS (
			SELECT id AS job_id FROM syslog_archive_jobs
			WHERE (
				status IN ('ready','failed') AND next_attempt_at<=now()
			) OR (
				$3 AND status='pending' AND next_attempt_at<=now()
			) OR (
				status='uploading' AND lease_expires_at<now()
			) OR (
				$3 AND status='building' AND lease_expires_at<now()
			)
			ORDER BY
				CASE status
					WHEN 'ready' THEN 0
					WHEN 'failed' THEN 1
					WHEN 'uploading' THEN 2
					WHEN 'building' THEN 3
					WHEN 'pending' THEN 4
					ELSE 5
				END,
				CASE WHEN status IN ('pending','building') THEN hour_start END DESC NULLS LAST,
				CASE WHEN status IN ('ready','failed','uploading') THEN hour_start END ASC,
				next_attempt_at, id
			FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE syslog_archive_jobs j SET
			status=CASE
				WHEN j.status IN ('ready','failed','uploading') THEN 'uploading'
				ELSE 'building'
			END,
			worker_id=$1,
			heartbeat_at=now(),
			lease_expires_at=now()+make_interval(secs=>$2),
			attempts=CASE
				WHEN j.status IN ('building','uploading') AND j.lease_expires_at<now()
					THEN j.attempts
				WHEN j.status IN ('ready','failed','pending') THEN j.attempts+1
				ELSE j.attempts
			END,
			updated_at=now()
		FROM candidate WHERE j.id=candidate.job_id
		RETURNING `+syslogArchiveJobColumns, workerID, secs, allowBuild))
	if errors.Is(err, pgx.ErrNoRows) {
		return SyslogArchiveJob{}, ErrNotFound
	}
	return job, err
}

func (s *Store) HeartbeatSyslogArchiveJob(
	ctx context.Context, jobID uuid.UUID, workerID string, lease time.Duration,
) error {
	if lease <= 0 {
		lease = DefaultSyslogArchiveLease
	}
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			heartbeat_at=now(),
			lease_expires_at=now()+make_interval(secs=>$3),
			updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status IN ('building','uploading')`,
		jobID, workerID, int(lease.Seconds()),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) MarkSyslogArchiveReady(
	ctx context.Context, jobID uuid.UUID, workerID, localPath string, bytes, payloadCount int64,
	maxReceivedAt *time.Time, maxEventID *uuid.UUID,
) error {
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='ready', local_path=$3, bytes=$4, payload_count=$5,
			max_received_at=$6, max_event_id=$7, last_error='',
			worker_id=NULL, heartbeat_at=NULL, lease_expires_at=NULL,
			next_attempt_at=now(), updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status='building'`,
		jobID, workerID, localPath, bytes, payloadCount, maxReceivedAt, maxEventID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) PromoteSyslogArchiveUploading(
	ctx context.Context, jobID uuid.UUID, workerID string, lease time.Duration,
) error {
	if lease <= 0 {
		lease = DefaultSyslogArchiveLease
	}
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='uploading', worker_id=$2, heartbeat_at=now(),
			lease_expires_at=now()+make_interval(secs=>$3), updated_at=now()
		WHERE id=$1 AND status='ready'`,
		jobID, workerID, int(lease.Seconds()),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) MarkSyslogArchiveUploaded(
	ctx context.Context, jobID uuid.UUID, workerID string,
) error {
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='uploaded', uploaded_at=now(), local_path='', last_error='',
			worker_id=NULL, heartbeat_at=NULL, lease_expires_at=NULL, updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status='uploading'`,
		jobID, workerID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) FailSyslogArchiveJob(
	ctx context.Context, jobID uuid.UUID, workerID, message string, retryAfter time.Duration, keepLocal bool,
) error {
	if retryAfter <= 0 {
		retryAfter = time.Minute
	}
	status := SyslogArchiveStatusFailed
	localClear := ""
	if keepLocal {
		localClear = "local_path" // keep column
	}
	_ = localClear
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status=$4,
			last_error=$3,
			next_attempt_at=now()+make_interval(secs=>$5),
			worker_id=NULL, heartbeat_at=NULL, lease_expires_at=NULL,
			local_path=CASE WHEN $6 THEN local_path ELSE '' END,
			updated_at=now()
		WHERE id=$1 AND (worker_id=$2 OR worker_id IS NULL)
			AND status IN ('building','uploading','ready','failed','pending')`,
		jobID, workerID, message, status, int(retryAfter.Seconds()), keepLocal,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AbandonSyslogArchiveJob(
	ctx context.Context, jobID uuid.UUID, workerID, message string,
) error {
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='abandoned', last_error=$3,
			worker_id=NULL, heartbeat_at=NULL, lease_expires_at=NULL, updated_at=now()
		WHERE id=$1 AND (worker_id=$2 OR worker_id IS NULL)`,
		jobID, workerID, message,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SyslogArchiveSpoolBytes(ctx context.Context) (int64, error) {
	var total int64
	err := s.DB.QueryRow(ctx, `
		SELECT COALESCE(SUM(bytes),0) FROM syslog_archive_jobs
		WHERE status IN ('ready','failed','building','uploading') AND local_path<>''`).Scan(&total)
	return total, err
}

func (s *Store) ListSyslogArchiveDevices(ctx context.Context) ([]Device, error) {
	rows, err := s.DB.Query(ctx, `SELECT `+deviceSelectColumns+`
		FROM devices
		WHERE enabled AND purge_state='active' AND syslog_archive_enabled
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
		result = append(result, device)
	}
	return result, rows.Err()
}

func (s *Store) TrySyslogRawGCLock(ctx context.Context) (func(), bool, error) {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, syslogRawGCLockKey).
		Scan(&acquired); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !acquired {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, syslogRawGCLockKey)
		conn.Release()
	}, true, nil
}

func (s *Store) SyslogUTCHourBlocked(ctx context.Context, deviceID uuid.UUID, hourStart time.Time) (bool, error) {
	hour := hourStart.UTC().Truncate(time.Hour)
	var blocked bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM syslog_raw_gc
		WHERE device_id=$1 AND hour_start_utc=$2
		  AND (sealed_at IS NOT NULL OR raw_deleted_at IS NOT NULL)
	) OR EXISTS (
		SELECT 1 FROM syslog_raw_history_cutoff
		WHERE cutoff > $2
	)`, deviceID, hour).Scan(&blocked)
	return blocked, err
}

func (s *Store) SetSyslogRawHistoryCutoff(ctx context.Context, cutoff time.Time) error {
	_, err := s.DB.Exec(ctx, `
		INSERT INTO syslog_raw_history_cutoff (k, cutoff) VALUES (1, $1)
		ON CONFLICT (k) DO UPDATE SET cutoff=GREATEST(syslog_raw_history_cutoff.cutoff, EXCLUDED.cutoff)`,
		cutoff.UTC())
	return err
}

func (s *Store) RequeueSyslogArchiveIfStaleFingerprint(
	ctx context.Context, jobID uuid.UUID, payloadCount int64, maxReceivedAt *time.Time, maxEventID *uuid.UUID,
) (bool, error) {
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='pending', next_attempt_at=now(), last_error='fingerprint changed',
			local_path='', updated_at=now()
		WHERE id=$1 AND status IN ('ready','failed','uploaded')
		  AND (
			payload_count IS DISTINCT FROM $2
			OR max_received_at IS DISTINCT FROM $3
			OR max_event_id IS DISTINCT FROM $4
		  )`,
		jobID, payloadCount, maxReceivedAt, maxEventID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) ArchiveJobsForUTCHour(
	ctx context.Context, deviceID uuid.UUID, hourStart time.Time,
) (pending, archived int, err error) {
	from := hourStart.UTC().Truncate(time.Hour)
	to := from.Add(time.Hour)
	err = s.DB.QueryRow(ctx, `
		SELECT count(*) FROM syslog_archive_jobs
		WHERE device_id=$1
		  AND hour_start < $3
		  AND hour_start + interval '10 minutes' > $2
		  AND status NOT IN ('ready','uploaded','skipped_stale','abandoned')`,
		deviceID, from, to).Scan(&pending)
	if err != nil {
		return 0, 0, err
	}
	err = s.DB.QueryRow(ctx, `
		SELECT count(*) FROM syslog_archive_jobs
		WHERE device_id=$1
		  AND hour_start < $3
		  AND hour_start + interval '10 minutes' > $2
		  AND status IN ('ready','uploaded')`,
		deviceID, from, to).Scan(&archived)
	return pending, archived, err
}

func (s *Store) ListSyslogArchiveJobsOverlappingUTCHour(
	ctx context.Context, deviceID uuid.UUID, hourStart time.Time,
) ([]SyslogArchiveJob, error) {
	from := hourStart.UTC().Truncate(time.Hour)
	to := from.Add(time.Hour)
	rows, err := s.DB.Query(ctx, `
		SELECT `+syslogArchiveJobColumns+`
		FROM syslog_archive_jobs
		WHERE device_id=$1
		  AND hour_start < $3
		  AND hour_start + interval '10 minutes' > $2
		  AND status IN ('ready','uploaded','failed')
		ORDER BY hour_start`,
		deviceID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []SyslogArchiveJob
	for rows.Next() {
		job, scanErr := scanSyslogArchiveJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *Store) AbandonSyslogArchiveJobsForDevice(ctx context.Context, deviceID uuid.UUID, reason string) error {
	_, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='abandoned', last_error=$2, worker_id=NULL,
			heartbeat_at=NULL, lease_expires_at=NULL, updated_at=now()
		WHERE device_id=$1 AND status NOT IN ('uploaded','abandoned','skipped_stale')`,
		deviceID, reason)
	return err
}
