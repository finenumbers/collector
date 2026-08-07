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
	DefaultSyslogArchiveLease              = 45 * time.Second
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
	local_path,bytes,attempts,last_error,next_attempt_at,COALESCE(worker_id,''),heartbeat_at,
	lease_expires_at,uploaded_at,created_at,updated_at`

func scanSyslogArchiveJob(row pgx.Row) (SyslogArchiveJob, error) {
	var job SyslogArchiveJob
	err := row.Scan(
		&job.ID, &job.DeviceID, &job.HourStart, &job.ArchiveName, &job.RemoteDir, &job.Timezone,
		&job.Status, &job.LocalPath, &job.Bytes, &job.Attempts, &job.LastError, &job.NextAttemptAt,
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
func (s *Store) ClaimSyslogArchiveJob(
	ctx context.Context, workerID string, lease time.Duration,
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
				status='pending' AND next_attempt_at<=now()
			) OR (
				status IN ('building','uploading') AND lease_expires_at<now()
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
				next_attempt_at, created_at, id
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
		RETURNING `+syslogArchiveJobColumns, workerID, secs))
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
	ctx context.Context, jobID uuid.UUID, workerID, localPath string, bytes int64,
) error {
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='ready', local_path=$3, bytes=$4, last_error='',
			worker_id=NULL, heartbeat_at=NULL, lease_expires_at=NULL,
			next_attempt_at=now(), updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status='building'`,
		jobID, workerID, localPath, bytes,
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
