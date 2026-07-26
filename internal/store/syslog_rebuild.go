package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SyslogParserRebuildJob is the PostgreSQL checkpoint for one immutable
// device/parser replay range. Cursor updates happen only after ClickHouse
// derived writes and the replay ledger have succeeded.
type SyslogParserRebuildJob struct {
	DeviceID            uuid.UUID
	ParserVersion       string
	Status              string
	CursorReceivedUS    int64
	CursorEventID       uuid.UUID
	WatermarkReceivedUS int64
	WatermarkEventID    uuid.UUID
	TotalEvents         uint64
	ProcessedEvents     uint64
	ProcessedBatches    uint64
	Attempts            uint32
	LastBatchEvents     uint32
	Error               string
	HeartbeatAt         *time.Time
	NextAttemptAt       time.Time
	StartedAt           *time.Time
	CompletedAt         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

func (s *Store) HasSyslogParserRebuildJob(
	ctx context.Context, deviceID uuid.UUID, parserVersion string,
) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM syslog_parser_rebuild_jobs
		WHERE device_id=$1 AND parser_version=$2
	)`, deviceID, parserVersion).Scan(&exists)
	return exists, err
}

func (s *Store) HasActiveSyslogParserRebuildJobs(
	ctx context.Context, parserVersion string,
) (bool, error) {
	var exists bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM syslog_parser_rebuild_jobs
		WHERE parser_version=$1 AND status IN ('pending','running')
	)`, parserVersion).Scan(&exists)
	return exists, err
}

func (s *Store) EnsureSyslogParserRebuildJob(
	ctx context.Context,
	deviceID uuid.UUID,
	parserVersion string,
	watermarkReceivedUS int64,
	watermarkEventID uuid.UUID,
	totalEvents uint64,
) error {
	status := "pending"
	completedAt := any(nil)
	if totalEvents == 0 {
		status = "completed"
		completedAt = time.Now().UTC()
	}
	_, err := s.DB.Exec(ctx, `INSERT INTO syslog_parser_rebuild_jobs
		(device_id,parser_version,status,watermark_received_us,watermark_event_id,
		 total_events,completed_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT(device_id,parser_version) DO NOTHING`,
		deviceID, parserVersion, status, watermarkReceivedUS, watermarkEventID,
		totalEvents, completedAt)
	return err
}

func (s *Store) SetSyslogParserRebuildPaused(
	ctx context.Context, parserVersion string, paused bool,
) error {
	if paused {
		_, err := s.DB.Exec(ctx, `UPDATE syslog_parser_rebuild_jobs
			SET status='paused',heartbeat_at=now(),updated_at=now()
			WHERE parser_version=$1
			  AND (status='pending'
			    OR (status='running' AND heartbeat_at < now()-interval '5 minutes'))`,
			parserVersion)
		return err
	}
	_, err := s.DB.Exec(ctx, `UPDATE syslog_parser_rebuild_jobs
		SET status='pending',next_attempt_at=now(),heartbeat_at=now(),updated_at=now()
		WHERE parser_version=$1 AND status='paused'`, parserVersion)
	return err
}

func (s *Store) ClaimSyslogParserRebuildJob(
	ctx context.Context, parserVersion string, staleAfter time.Duration,
) (SyslogParserRebuildJob, error) {
	if staleAfter <= 0 {
		staleAfter = 5 * time.Minute
	}
	var job SyslogParserRebuildJob
	err := s.DB.QueryRow(ctx, `WITH candidate AS (
			SELECT device_id,parser_version
			FROM syslog_parser_rebuild_jobs
			WHERE parser_version=$1
			  AND (status='pending'
			    OR (status='running' AND heartbeat_at < now()-$2::interval))
			  AND next_attempt_at<=now()
			ORDER BY next_attempt_at,updated_at,device_id
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE syslog_parser_rebuild_jobs AS j
		SET status='running',attempts=j.attempts+1,
		    started_at=COALESCE(j.started_at,now()),heartbeat_at=now(),updated_at=now()
		FROM candidate c
		WHERE j.device_id=c.device_id AND j.parser_version=c.parser_version
		RETURNING j.device_id,j.parser_version,j.status,j.cursor_received_us,
			j.cursor_event_id,j.watermark_received_us,j.watermark_event_id,
			j.total_events,j.processed_events,j.processed_batches,j.attempts,
			j.last_batch_events,COALESCE(j.error,''),j.heartbeat_at,j.started_at,
			j.completed_at,j.next_attempt_at,j.created_at,j.updated_at`,
		parserVersion, staleAfter.String()).Scan(
		&job.DeviceID, &job.ParserVersion, &job.Status, &job.CursorReceivedUS,
		&job.CursorEventID, &job.WatermarkReceivedUS, &job.WatermarkEventID,
		&job.TotalEvents, &job.ProcessedEvents, &job.ProcessedBatches, &job.Attempts,
		&job.LastBatchEvents, &job.Error, &job.HeartbeatAt, &job.StartedAt,
		&job.CompletedAt, &job.NextAttemptAt, &job.CreatedAt, &job.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return SyslogParserRebuildJob{}, ErrNotFound
	}
	return job, err
}

func (s *Store) ListSyslogParserRebuildJobs(
	ctx context.Context, parserVersion string,
) ([]SyslogParserRebuildJob, error) {
	rows, err := s.DB.Query(ctx, `SELECT device_id,parser_version,status,cursor_received_us,
		cursor_event_id,watermark_received_us,watermark_event_id,total_events,
		processed_events,processed_batches,attempts,last_batch_events,COALESCE(error,''),
		heartbeat_at,started_at,completed_at,next_attempt_at,created_at,updated_at
		FROM syslog_parser_rebuild_jobs
		WHERE ($1='' OR parser_version=$1)
		ORDER BY
			CASE status WHEN 'running' THEN 0 WHEN 'pending' THEN 1
				WHEN 'paused' THEN 2 ELSE 3 END,
			updated_at DESC,device_id`, parserVersion)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]SyslogParserRebuildJob, 0)
	for rows.Next() {
		var job SyslogParserRebuildJob
		if err := rows.Scan(
			&job.DeviceID, &job.ParserVersion, &job.Status, &job.CursorReceivedUS,
			&job.CursorEventID, &job.WatermarkReceivedUS, &job.WatermarkEventID,
			&job.TotalEvents, &job.ProcessedEvents, &job.ProcessedBatches, &job.Attempts,
			&job.LastBatchEvents, &job.Error, &job.HeartbeatAt, &job.StartedAt,
			&job.CompletedAt, &job.NextAttemptAt, &job.CreatedAt, &job.UpdatedAt,
		); err != nil {
			return nil, err
		}
		result = append(result, job)
	}
	return result, rows.Err()
}

func (s *Store) AdvanceSyslogParserRebuildJob(
	ctx context.Context,
	job SyslogParserRebuildJob,
	cursorReceivedUS int64,
	cursorEventID uuid.UUID,
	batchEvents uint64,
) error {
	tag, err := s.DB.Exec(ctx, `UPDATE syslog_parser_rebuild_jobs
		SET status='pending',cursor_received_us=$3,cursor_event_id=$4,
		    processed_events=processed_events+$5,processed_batches=processed_batches+1,
		    last_batch_events=$5,error=NULL,heartbeat_at=now(),next_attempt_at=now(),
		    updated_at=now()
		WHERE device_id=$1 AND parser_version=$2 AND status='running'
		  AND cursor_received_us=$6 AND cursor_event_id=$7`,
		job.DeviceID, job.ParserVersion, cursorReceivedUS, cursorEventID, batchEvents,
		job.CursorReceivedUS, job.CursorEventID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("syslog parser rebuild checkpoint changed concurrently")
	}
	return nil
}

func (s *Store) HeartbeatSyslogParserRebuildJob(
	ctx context.Context, job SyslogParserRebuildJob,
) error {
	_, err := s.DB.Exec(ctx, `UPDATE syslog_parser_rebuild_jobs
		SET heartbeat_at=now(),updated_at=now()
		WHERE device_id=$1 AND parser_version=$2 AND status='running'`,
		job.DeviceID, job.ParserVersion)
	return err
}

func (s *Store) CompleteSyslogParserRebuildJob(
	ctx context.Context, job SyslogParserRebuildJob,
) error {
	tag, err := s.DB.Exec(ctx, `UPDATE syslog_parser_rebuild_jobs
		SET status='completed',
		    cursor_received_us=watermark_received_us,cursor_event_id=watermark_event_id,
		    last_batch_events=0,
		    error=NULL,
		    heartbeat_at=now(),completed_at=now(),updated_at=now()
		WHERE device_id=$1 AND parser_version=$2 AND status='running'
		  AND cursor_received_us=$3 AND cursor_event_id=$4`,
		job.DeviceID, job.ParserVersion, job.CursorReceivedUS, job.CursorEventID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("syslog parser rebuild completion changed concurrently")
	}
	return nil
}

func (s *Store) RetrySyslogParserRebuildJob(
	ctx context.Context, job SyslogParserRebuildJob, rebuildErr error, retryAfter time.Duration,
) error {
	message := "unknown replay error"
	if rebuildErr != nil {
		message = rebuildErr.Error()
	}
	if len(message) > 8_000 {
		message = message[:8_000]
	}
	if retryAfter < 0 {
		retryAfter = 0
	}
	_, err := s.DB.Exec(ctx, `UPDATE syslog_parser_rebuild_jobs
		SET status='pending',error=$3,heartbeat_at=now(),
		    next_attempt_at=now()+$4::interval,updated_at=now()
		WHERE device_id=$1 AND parser_version=$2 AND status='running'`,
		job.DeviceID, job.ParserVersion, message, retryAfter.String())
	return err
}
