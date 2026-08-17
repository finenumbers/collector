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

	syslogArchiveOrchestratorLockKey    int64 = 0x53594C4152434831 // SYLARCH1
	DefaultSyslogArchiveLease                 = 2 * time.Minute
	SyslogArchiveWorkerHeartbeatTimeout       = 45 * time.Second
	SyslogArchiveJobLogWindow                 = 24 * time.Hour
	syslogRawGCLockKey                  int64 = 0x53594C5241574731 // SYLRAWG1
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
	DeviceName    string     `json:"deviceName,omitempty"`
	DeviceSign    string     `json:"deviceSign,omitempty"`
}

type SyslogArchiveWorkerState struct {
	WorkerID    string     `json:"workerId,omitempty"`
	HeartbeatAt *time.Time `json:"heartbeatAt,omitempty"`
	LastTickAt  *time.Time `json:"lastTickAt,omitempty"`
	LastError   string     `json:"lastError,omitempty"`
	Alive       bool       `json:"alive"`
}

type SyslogArchiveJobCounts struct {
	Pending      int64 `json:"pending"`
	Building     int64 `json:"building"`
	Ready        int64 `json:"ready"`
	Uploading    int64 `json:"uploading"`
	Uploaded     int64 `json:"uploaded"`
	Failed       int64 `json:"failed"`
	Abandoned    int64 `json:"abandoned"`
	SkippedStale int64 `json:"skippedStale"`
}

const syslogArchiveJobColumns = `id,device_id,hour_start,archive_name,remote_dir,timezone,status,
	local_path,bytes,payload_count,max_received_at,max_event_id,attempts,last_error,next_attempt_at,
	COALESCE(worker_id,''),heartbeat_at,lease_expires_at,uploaded_at,created_at,updated_at`

const syslogArchiveJobColumnsPrefixed = `j.id,j.device_id,j.hour_start,j.archive_name,j.remote_dir,j.timezone,j.status,
	j.local_path,j.bytes,j.payload_count,j.max_received_at,j.max_event_id,j.attempts,j.last_error,j.next_attempt_at,
	COALESCE(j.worker_id,''),j.heartbeat_at,j.lease_expires_at,j.uploaded_at,j.created_at,j.updated_at`

func scanSyslogArchiveJob(row pgx.Row) (SyslogArchiveJob, error) {
	return scanSyslogArchiveJobExtra(row)
}

func scanSyslogArchiveJobExtra(row pgx.Row, extra ...any) (SyslogArchiveJob, error) {
	var job SyslogArchiveJob
	args := []any{
		&job.ID, &job.DeviceID, &job.HourStart, &job.ArchiveName, &job.RemoteDir, &job.Timezone,
		&job.Status, &job.LocalPath, &job.Bytes, &job.PayloadCount, &job.MaxReceivedAt, &job.MaxEventID,
		&job.Attempts, &job.LastError, &job.NextAttemptAt,
		&job.WorkerID, &job.HeartbeatAt, &job.LeaseExpires, &job.UploadedAt, &job.CreatedAt, &job.UpdatedAt,
	}
	args = append(args, extra...)
	err := row.Scan(args...)
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
			archive_name=CASE
				WHEN syslog_archive_jobs.status IN ('pending','failed','ready')
				THEN EXCLUDED.archive_name ELSE syslog_archive_jobs.archive_name END,
			remote_dir=CASE
				WHEN syslog_archive_jobs.status IN ('pending','failed','ready')
				THEN EXCLUDED.remote_dir ELSE syslog_archive_jobs.remote_dir END,
			timezone=CASE
				WHEN syslog_archive_jobs.status IN ('pending','failed','ready')
				THEN EXCLUDED.timezone ELSE syslog_archive_jobs.timezone END,
			updated_at=CASE
				WHEN syslog_archive_jobs.status IN ('pending','failed','ready')
				 AND (
					syslog_archive_jobs.archive_name IS DISTINCT FROM EXCLUDED.archive_name
					OR syslog_archive_jobs.remote_dir IS DISTINCT FROM EXCLUDED.remote_dir
					OR syslog_archive_jobs.timezone IS DISTINCT FROM EXCLUDED.timezone
				 )
				THEN now() ELSE syslog_archive_jobs.updated_at END
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
				status='ready' AND next_attempt_at<=now()
			) OR (
				status='failed' AND local_path<>'' AND next_attempt_at<=now()
			) OR (
				$3 AND status='failed' AND local_path='' AND next_attempt_at<=now()
			) OR (
				$3 AND status='pending' AND next_attempt_at<=now()
			) OR (
				status='uploading' AND local_path<>'' AND lease_expires_at<now()
			) OR (
				$3 AND status='uploading' AND local_path='' AND lease_expires_at<now()
			) OR (
				$3 AND status='building' AND lease_expires_at<now()
			)
			ORDER BY
				CASE
					WHEN status='ready' THEN 0
					WHEN status='failed' AND local_path<>'' THEN 1
					WHEN status='uploading' AND local_path<>'' THEN 2
					WHEN status='building' THEN 3
					WHEN status IN ('pending') OR ((status IN ('failed','uploading')) AND local_path='') THEN 4
					ELSE 5
				END,
				CASE WHEN status IN ('pending','building') OR ((status IN ('failed','uploading')) AND local_path='')
					THEN hour_start END DESC NULLS LAST,
				CASE WHEN status IN ('ready') OR ((status IN ('failed','uploading')) AND local_path<>'')
					THEN hour_start END ASC,
				next_attempt_at, id
			FOR UPDATE SKIP LOCKED LIMIT 1
		)
		UPDATE syslog_archive_jobs j SET
			status=CASE
				WHEN j.status='ready' THEN 'uploading'
				WHEN j.status IN ('failed','uploading') AND j.local_path<>'' THEN 'uploading'
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
	ctx context.Context, jobID uuid.UUID, workerID, remoteDir string,
) error {
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET
			status='uploaded', uploaded_at=now(), local_path='', last_error='',
			remote_dir=CASE WHEN $3<>'' THEN $3 ELSE remote_dir END,
			worker_id=NULL, heartbeat_at=NULL, lease_expires_at=NULL, updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status='uploading'`,
		jobID, workerID, remoteDir,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) SetSyslogArchiveRemoteDirQuiet(ctx context.Context, jobID uuid.UUID, remoteDir string) error {
	tag, err := s.DB.Exec(ctx, `
		UPDATE syslog_archive_jobs SET remote_dir=$2
		WHERE id=$1 AND status='uploaded' AND remote_dir IS DISTINCT FROM $2`,
		jobID, remoteDir,
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

func (s *Store) GetSyslogArchiveJob(ctx context.Context, jobID uuid.UUID) (SyslogArchiveJob, error) {
	job, err := scanSyslogArchiveJob(s.DB.QueryRow(ctx,
		`SELECT `+syslogArchiveJobColumns+` FROM syslog_archive_jobs WHERE id=$1`, jobID))
	if errors.Is(err, pgx.ErrNoRows) {
		return SyslogArchiveJob{}, ErrNotFound
	}
	return job, err
}

func (s *Store) ListSyslogArchiveJobsPage(
	ctx context.Context, limit int, before time.Time, beforeID uuid.UUID,
) ([]SyslogArchiveJob, bool, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	rows, err := s.DB.Query(ctx, `
		SELECT `+syslogArchiveJobColumnsPrefixed+`,
			COALESCE(d.name,''), COALESCE(d.device_sign,'')
		FROM syslog_archive_jobs j
		JOIN devices d ON d.id=j.device_id
		WHERE (
			j.updated_at >= now()-make_interval(secs=>$2)
			OR j.status IN ('pending','building','ready','uploading','failed')
		)
		AND (
			$3::timestamptz IS NULL
			OR (j.updated_at, j.id) < ($3, $4)
		)
		ORDER BY j.updated_at DESC, j.id DESC
		LIMIT $1`, limit+1, int(SyslogArchiveJobLogWindow.Seconds()), nullableTime(before), beforeID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var jobs []SyslogArchiveJob
	for rows.Next() {
		var name, sign string
		job, scanErr := scanSyslogArchiveJobExtra(rows, &name, &sign)
		if scanErr != nil {
			return nil, false, scanErr
		}
		job.DeviceName = name
		job.DeviceSign = sign
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(jobs) > limit
	if hasMore {
		jobs = jobs[:limit]
	}
	return jobs, hasMore, nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func (s *Store) ListSyslogArchiveUploadedForRelocate(ctx context.Context, limit int) ([]SyslogArchiveJob, error) {
	if limit <= 0 || limit > 100 {
		limit = 40
	}
	rows, err := s.DB.Query(ctx, `
		SELECT `+syslogArchiveJobColumns+`
		FROM syslog_archive_jobs
		WHERE status='uploaded'
		  AND archive_name ~ '_[0-9]{2}-[0-9]{2}\.zip$'
		  AND remote_dir NOT LIKE '%/' || substring(archive_name from '_([0-9]{2}\\.[0-9]{2}\\.[0-9]{4})_')
		ORDER BY hour_start DESC
		LIMIT $1`, limit)
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

func (s *Store) ListRecentSyslogArchiveJobs(ctx context.Context, limit int) ([]SyslogArchiveJob, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.DB.Query(ctx, `
		SELECT `+syslogArchiveJobColumnsPrefixed+`,
			COALESCE(d.name,''), COALESCE(d.device_sign,'')
		FROM syslog_archive_jobs j
		JOIN devices d ON d.id=j.device_id
		ORDER BY j.updated_at DESC, j.hour_start DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []SyslogArchiveJob
	for rows.Next() {
		var name, sign string
		job, scanErr := scanSyslogArchiveJobExtra(rows, &name, &sign)
		if scanErr != nil {
			return nil, scanErr
		}
		job.DeviceName = name
		job.DeviceSign = sign
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *Store) SyslogArchiveJobCounts(ctx context.Context) (SyslogArchiveJobCounts, error) {
	var counts SyslogArchiveJobCounts
	err := s.DB.QueryRow(ctx, `
		SELECT
			count(*) FILTER (WHERE status='pending'),
			count(*) FILTER (WHERE status='building'),
			count(*) FILTER (WHERE status='ready'),
			count(*) FILTER (WHERE status='uploading'),
			count(*) FILTER (WHERE status='uploaded' AND uploaded_at >= now()-make_interval(secs=>$1)),
			count(*) FILTER (WHERE status='failed'),
			count(*) FILTER (WHERE status='abandoned'),
			count(*) FILTER (WHERE status='skipped_stale')
		FROM syslog_archive_jobs`, int(SyslogArchiveJobLogWindow.Seconds())).Scan(
		&counts.Pending, &counts.Building, &counts.Ready, &counts.Uploading,
		&counts.Uploaded, &counts.Failed, &counts.Abandoned, &counts.SkippedStale,
	)
	return counts, err
}

type SyslogArchiveDeviceProgress struct {
	DeviceID       uuid.UUID
	LastUploadedAt *time.Time
	LastUploaded   *time.Time
	LastError      string
	NameMismatch   bool
}

func (s *Store) SyslogArchiveDeviceProgress(ctx context.Context) ([]SyslogArchiveDeviceProgress, error) {
	rows, err := s.DB.Query(ctx, `
		SELECT device_id,
			max(uploaded_at) FILTER (WHERE status='uploaded'),
			max(hour_start) FILTER (WHERE status='uploaded'),
			COALESCE((
				SELECT last_error FROM syslog_archive_jobs e
				WHERE e.device_id=j.device_id AND e.last_error<>''
				  AND e.status NOT IN ('abandoned','skipped_stale')
				ORDER BY e.updated_at DESC LIMIT 1
			),''),
			EXISTS (
				SELECT 1 FROM syslog_archive_jobs h
				WHERE h.device_id=j.device_id
				  AND h.status='uploaded'
				  AND h.archive_name ~ '_[0-9]{2}\.zip$'
				  AND h.archive_name !~ '_[0-9]{2}-[0-9]{2}\.zip$'
			)
		FROM syslog_archive_jobs j
		GROUP BY device_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []SyslogArchiveDeviceProgress
	for rows.Next() {
		var item SyslogArchiveDeviceProgress
		if err := rows.Scan(
			&item.DeviceID, &item.LastUploadedAt, &item.LastUploaded,
			&item.LastError, &item.NameMismatch,
		); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) TouchSyslogArchiveWorker(ctx context.Context, workerID string) error {
	_, err := s.DB.Exec(ctx, `
		INSERT INTO syslog_archive_worker (k, worker_id, heartbeat_at, updated_at)
		VALUES (1, $1, now(), now())
		ON CONFLICT (k) DO UPDATE SET
			worker_id=EXCLUDED.worker_id,
			heartbeat_at=now(),
			updated_at=now()`, workerID)
	return err
}

func (s *Store) NoteSyslogArchiveWorkerTick(ctx context.Context, workerID, lastError string) error {
	_, err := s.DB.Exec(ctx, `
		INSERT INTO syslog_archive_worker (k, worker_id, heartbeat_at, last_tick_at, last_error, updated_at)
		VALUES (1, $1, now(), now(), $2, now())
		ON CONFLICT (k) DO UPDATE SET
			worker_id=EXCLUDED.worker_id,
			heartbeat_at=now(),
			last_tick_at=now(),
			last_error=$2,
			updated_at=now()`, workerID, lastError)
	return err
}

func (s *Store) SyslogArchiveWorkerState(ctx context.Context, maxAge time.Duration) (SyslogArchiveWorkerState, error) {
	if maxAge <= 0 {
		maxAge = SyslogArchiveWorkerHeartbeatTimeout
	}
	var state SyslogArchiveWorkerState
	var heartbeat, tick *time.Time
	err := s.DB.QueryRow(ctx, `
		SELECT worker_id, heartbeat_at, last_tick_at, last_error,
			heartbeat_at IS NOT NULL AND heartbeat_at >= now()-make_interval(secs=>$1)
		FROM syslog_archive_worker WHERE k=1`, int(maxAge.Seconds()),
	).Scan(&state.WorkerID, &heartbeat, &tick, &state.LastError, &state.Alive)
	if errors.Is(err, pgx.ErrNoRows) {
		return SyslogArchiveWorkerState{}, nil
	}
	if err != nil {
		return SyslogArchiveWorkerState{}, err
	}
	state.HeartbeatAt = heartbeat
	state.LastTickAt = tick
	return state, nil
}
