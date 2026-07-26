package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrExportQueueFull = errors.New("export queue limit reached")
	ErrExportConflict  = errors.New("export job cannot be changed in its current state")
)

const (
	MaxQueuedExportsPerUser   = 3
	MaxActiveExportsPerDevice = 5
	QueuedExportTimeout       = 10 * time.Minute
	ExportHeartbeatTimeout    = 2 * time.Minute
)

type ExportJob struct {
	ID                 uuid.UUID  `json:"id"`
	RequestedBy        uuid.UUID  `json:"requestedBy"`
	DeviceID           uuid.UUID  `json:"deviceId"`
	Dataset            string     `json:"dataset"`
	Category           string     `json:"category,omitempty"`
	Search             string     `json:"search,omitempty"`
	RangeFrom          *time.Time `json:"rangeFrom,omitempty"`
	RangeTo            *time.Time `json:"rangeTo,omitempty"`
	Format             string     `json:"format"`
	OutputFormat       string     `json:"outputFormat,omitempty"`
	Status             string     `json:"status"`
	Filename           string     `json:"filename,omitempty"`
	ContentType        string     `json:"contentType,omitempty"`
	ObjectKey          string     `json:"-"`
	SizeBytes          *int64     `json:"sizeBytes,omitempty"`
	SHA256             string     `json:"sha256,omitempty"`
	RowsEstimated      *int64     `json:"rowsEstimated,omitempty"`
	RowsProcessed      int64      `json:"rowsProcessed"`
	BytesSpooled       int64      `json:"bytesSpooled"`
	ActiveRevision     int64      `json:"activeRevision"`
	Timezone           string     `json:"timezone"`
	TemplateKey        string     `json:"templateKey"`
	ParserVersion      string     `json:"parserVersion"`
	RawHighWatermark   *time.Time `json:"rawHighWatermark,omitempty"`
	RawHighWatermarkID *uuid.UUID `json:"rawHighWatermarkId,omitempty"`
	Error              string     `json:"error,omitempty"`
	CancelRequestedAt  *time.Time `json:"cancelRequestedAt,omitempty"`
	CreatedAt          time.Time  `json:"createdAt"`
	StartedAt          *time.Time `json:"startedAt,omitempty"`
	FinishedAt         *time.Time `json:"finishedAt,omitempty"`
	HeartbeatAt        *time.Time `json:"heartbeatAt,omitempty"`
	ExpiresAt          *time.Time `json:"expiresAt,omitempty"`
	WorkerID           string     `json:"-"`
}

type NewExportJob struct {
	DeviceID           uuid.UUID
	Dataset            string
	Category           string
	Search             string
	RangeFrom          *time.Time
	RangeTo            *time.Time
	Format             string
	RowsEstimated      *int64
	ActiveRevision     int64
	Timezone           string
	TemplateKey        string
	ParserVersion      string
	RawHighWatermark   *time.Time
	RawHighWatermarkID *uuid.UUID
}

type ExportJobCursor struct {
	CreatedAt time.Time
	ID        uuid.UUID
}

func scanExportJob(row pgx.Row) (ExportJob, error) {
	var job ExportJob
	err := row.Scan(
		&job.ID, &job.RequestedBy, &job.DeviceID, &job.Dataset, &job.Category, &job.Search,
		&job.RangeFrom, &job.RangeTo, &job.Format, &job.OutputFormat, &job.Status,
		&job.Filename, &job.ContentType, &job.ObjectKey, &job.SizeBytes, &job.SHA256,
		&job.RowsEstimated, &job.RowsProcessed, &job.BytesSpooled, &job.ActiveRevision,
		&job.Timezone, &job.TemplateKey, &job.ParserVersion, &job.RawHighWatermark,
		&job.RawHighWatermarkID, &job.Error, &job.CancelRequestedAt, &job.CreatedAt,
		&job.StartedAt, &job.FinishedAt, &job.HeartbeatAt, &job.ExpiresAt, &job.WorkerID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ExportJob{}, ErrNotFound
	}
	return job, err
}

const exportJobColumns = `id,requested_by,device_id,dataset,category,search,range_from,
	range_to,format,COALESCE(output_format,''),status,COALESCE(filename,''),
	COALESCE(content_type,''),COALESCE(object_key,''),size_bytes,COALESCE(sha256,''),
	rows_estimated,rows_processed,bytes_spooled,active_revision,timezone,template_key,
	parser_version,raw_high_watermark,raw_high_watermark_id,COALESCE(error,''),
	cancel_requested_at,created_at,started_at,finished_at,heartbeat_at,expires_at,
	COALESCE(worker_id,'')`

func (s *Store) CreateExportJob(
	ctx context.Context, input NewExportJob, actor User, remoteIP string,
) (ExportJob, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return ExportJob{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`,
		"export:"+input.DeviceID.String()); err != nil {
		return ExportJob{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE export_jobs SET status='failed',
		error='export worker timed out; retry the export',finished_at=now(),
		expires_at=now()+interval '7 days',lease_expires_at=NULL,updated_at=now()
		WHERE (status='queued' AND created_at<now()-make_interval(secs=>$1))
			OR (status='running' AND COALESCE(heartbeat_at,started_at,created_at)
				<now()-make_interval(secs=>$2))`,
		int64(QueuedExportTimeout/time.Second), int64(ExportHeartbeatTimeout/time.Second)); err != nil {
		return ExportJob{}, err
	}
	var userActive, deviceActive int
	if err = tx.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE requested_by=$1),
		count(*) FILTER (WHERE device_id=$2)
		FROM export_jobs WHERE status IN ('queued','running')`,
		actor.ID, input.DeviceID).Scan(&userActive, &deviceActive); err != nil {
		return ExportJob{}, err
	}
	if userActive >= MaxQueuedExportsPerUser || deviceActive >= MaxActiveExportsPerDevice {
		return ExportJob{}, ErrExportQueueFull
	}
	if input.Format == "" {
		input.Format = "auto"
	}
	filters, _ := json.Marshal(map[string]any{
		"category": input.Category, "q": input.Search,
		"from": input.RangeFrom, "to": input.RangeTo,
	})
	job, err := scanExportJob(tx.QueryRow(ctx, `INSERT INTO export_jobs
		(requested_by,device_id,dataset,filters,category,search,range_from,range_to,format,
		 rows_estimated,active_revision,timezone,template_key,parser_version,
		 raw_high_watermark,raw_high_watermark_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING `+exportJobColumns,
		actor.ID, input.DeviceID, input.Dataset, filters, input.Category, input.Search,
		input.RangeFrom, input.RangeTo, input.Format, input.RowsEstimated,
		input.ActiveRevision, input.Timezone, input.TemplateKey, input.ParserVersion,
		input.RawHighWatermark, input.RawHighWatermarkID))
	if err != nil {
		return ExportJob{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,'export_request','export_job',$2,$3,$4)`,
		actor.ID, job.ID.String(), remoteIP, filters); err != nil {
		return ExportJob{}, err
	}
	return job, tx.Commit(ctx)
}

func (s *Store) ExportJob(ctx context.Context, deviceID, jobID uuid.UUID) (ExportJob, error) {
	return scanExportJob(s.DB.QueryRow(ctx, `SELECT `+exportJobColumns+
		` FROM export_jobs WHERE id=$1 AND device_id=$2`, jobID, deviceID))
}

func (s *Store) FailStaleExportJob(
	ctx context.Context, deviceID, jobID uuid.UUID, queuedAge, heartbeatAge time.Duration,
) (bool, error) {
	queuedSeconds := max(int64(queuedAge/time.Second), 1)
	heartbeatSeconds := max(int64(heartbeatAge/time.Second), 1)
	tag, err := s.DB.Exec(ctx, `UPDATE export_jobs SET status='failed',
		error='export worker timed out; retry the export',finished_at=now(),
		expires_at=now()+interval '7 days',lease_expires_at=NULL,updated_at=now()
		WHERE id=$1 AND device_id=$2 AND (
			(status='queued' AND created_at<now()-make_interval(secs=>$3))
			OR (status='running' AND COALESCE(heartbeat_at,started_at,created_at)
				<now()-make_interval(secs=>$4))
		)`, jobID, deviceID, queuedSeconds, heartbeatSeconds)
	return tag.RowsAffected() != 0, err
}

func (s *Store) FailQueuedExportJob(
	ctx context.Context, deviceID, jobID uuid.UUID, message string,
) (bool, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE export_jobs SET status='failed',error=$3,
		finished_at=now(),expires_at=now()+interval '7 days',updated_at=now()
		WHERE id=$1 AND device_id=$2 AND status='queued'`, jobID, deviceID, message)
	return tag.RowsAffected() != 0, err
}

func (s *Store) ListExportJobs(
	ctx context.Context, deviceID uuid.UUID, limit int, cursor *ExportJobCursor,
) ([]ExportJob, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	args := []any{deviceID, limit + 1}
	where := ""
	if cursor != nil {
		where = ` AND (created_at,id)<($3,$4)`
		args = append(args, cursor.CreatedAt, cursor.ID)
	}
	rows, err := s.DB.Query(ctx, `SELECT `+exportJobColumns+
		` FROM export_jobs WHERE device_id=$1`+where+
		` ORDER BY created_at DESC,id DESC LIMIT $2`, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	items := make([]ExportJob, 0, limit+1)
	for rows.Next() {
		job, scanErr := scanExportJob(rows)
		if scanErr != nil {
			return nil, false, scanErr
		}
		items = append(items, job)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	return items, hasMore, nil
}

func (s *Store) CancelExportJob(
	ctx context.Context, deviceID, jobID uuid.UUID, actor User, remoteIP string,
) (ExportJob, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return ExportJob{}, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE export_jobs SET
		cancel_requested_at=now(),updated_at=now(),
		status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END,
		finished_at=CASE WHEN status='queued' THEN now() ELSE finished_at END,
		expires_at=CASE WHEN status='queued' THEN now()+interval '7 days' ELSE expires_at END
		WHERE id=$1 AND device_id=$2 AND status IN ('queued','running')`, jobID, deviceID)
	if err != nil {
		return ExportJob{}, err
	}
	if tag.RowsAffected() == 0 {
		if _, getErr := s.ExportJob(ctx, deviceID, jobID); errors.Is(getErr, ErrNotFound) {
			return ExportJob{}, ErrNotFound
		}
		return ExportJob{}, ErrExportConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip)
		VALUES($1,'export_cancel','export_job',$2,$3)`,
		actor.ID, jobID.String(), remoteIP); err != nil {
		return ExportJob{}, err
	}
	job, err := scanExportJob(tx.QueryRow(ctx, `SELECT `+exportJobColumns+
		` FROM export_jobs WHERE id=$1 AND device_id=$2`, jobID, deviceID))
	if err != nil {
		return ExportJob{}, err
	}
	return job, tx.Commit(ctx)
}

func (s *Store) AuditExportDownload(
	ctx context.Context, jobID uuid.UUID, actor User, remoteIP string,
) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip)
		VALUES($1,'export_download','export_job',$2,$3)`,
		actor.ID, jobID.String(), remoteIP)
	return err
}

func (s *Store) ClaimExportJob(
	ctx context.Context, workerID string, lease time.Duration,
) (ExportJob, error) {
	seconds := max(int64(lease/time.Second), 1)
	if _, err := s.DB.Exec(ctx, `UPDATE export_jobs SET status='cancelled',
		finished_at=now(),expires_at=now()+interval '7 days',lease_expires_at=NULL,
		updated_at=now() WHERE status='running' AND cancel_requested_at IS NOT NULL
		AND lease_expires_at<now()`); err != nil {
		return ExportJob{}, err
	}
	return scanExportJob(s.DB.QueryRow(ctx, `WITH candidate AS (
		SELECT id AS job_id FROM export_jobs
		WHERE status='queued'
		   OR (status='running' AND lease_expires_at<now())
		ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
	)
	UPDATE export_jobs j SET status='running',worker_id=$1,
		started_at=COALESCE(started_at,now()),heartbeat_at=now(),
		lease_expires_at=now()+make_interval(secs=>$2),updated_at=now()
	FROM candidate WHERE j.id=candidate.job_id RETURNING `+exportJobColumns,
		workerID, seconds))
}

func (s *Store) UpdateExportProgress(
	ctx context.Context, jobID uuid.UUID, workerID string, rows, bytes int64, lease time.Duration,
) (bool, error) {
	seconds := max(int64(lease/time.Second), 1)
	var cancelled bool
	err := s.DB.QueryRow(ctx, `UPDATE export_jobs SET rows_processed=$3,
		bytes_spooled=$4,heartbeat_at=now(),lease_expires_at=now()+make_interval(secs=>$5),
		updated_at=now() WHERE id=$1 AND worker_id=$2 AND status='running'
		RETURNING cancel_requested_at IS NOT NULL`,
		jobID, workerID, rows, bytes, seconds).Scan(&cancelled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrExportConflict
	}
	return cancelled, err
}

func (s *Store) CompleteExportJob(
	ctx context.Context, jobID uuid.UUID, workerID, outputFormat, filename,
	contentType, objectKey, sha string, size, rows int64,
) error {
	tag, err := s.DB.Exec(ctx, `UPDATE export_jobs SET status='completed',
		output_format=$3,filename=$4,content_type=$5,object_key=$6,sha256=$7,
		size_bytes=$8,rows_processed=$9,bytes_spooled=$8,finished_at=now(),
		expires_at=now()+interval '7 days',lease_expires_at=NULL,updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status='running' AND cancel_requested_at IS NULL`,
		jobID, workerID, outputFormat, filename, contentType, objectKey, sha, size, rows)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrExportConflict
	}
	return nil
}

func (s *Store) FinishExportJob(
	ctx context.Context, jobID uuid.UUID, workerID, status, message string,
) error {
	if status != "failed" && status != "cancelled" {
		return fmt.Errorf("invalid terminal export status %q", status)
	}
	tag, err := s.DB.Exec(ctx, `UPDATE export_jobs SET status=$3,error=$4,
		finished_at=now(),expires_at=now()+interval '7 days',lease_expires_at=NULL,
		updated_at=now() WHERE id=$1 AND worker_id=$2 AND status='running'`,
		jobID, workerID, status, message)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrExportConflict
	}
	return err
}

func (s *Store) FinishExportJobWithArtifact(
	ctx context.Context, jobID uuid.UUID, workerID, status, message, objectKey string,
) error {
	if status != "failed" && status != "cancelled" {
		return fmt.Errorf("invalid terminal export status %q", status)
	}
	_, err := s.DB.Exec(ctx, `UPDATE export_jobs SET status=$3,error=$4,object_key=$5,
		finished_at=now(),expires_at=now(),lease_expires_at=NULL,updated_at=now()
		WHERE id=$1 AND worker_id=$2 AND status='running'`,
		jobID, workerID, status, message, objectKey)
	return err
}

type ExpiredExportArtifact struct {
	ID        uuid.UUID
	ObjectKey string
}

func (s *Store) ExpireExportJobs(ctx context.Context, limit int) ([]ExpiredExportArtifact, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.Query(ctx, `SELECT id,COALESCE(object_key,'') FROM export_jobs
		WHERE status IN ('completed','failed','cancelled') AND expires_at<=now()
		ORDER BY expires_at,id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ExpiredExportArtifact, 0, limit)
	for rows.Next() {
		var item ExpiredExportArtifact
		if err = rows.Scan(&item.ID, &item.ObjectKey); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) MarkExportExpired(ctx context.Context, id uuid.UUID) error {
	_, err := s.DB.Exec(ctx, `UPDATE export_jobs SET status='expired',object_key=NULL,
		updated_at=now() WHERE id=$1 AND status IN ('completed','failed','cancelled')
		AND expires_at<=now()`, id)
	return err
}
