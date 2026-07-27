package store

import (
	"context"
	"errors"
	"time"

	"collector/internal/reconciliation"
	"collector/internal/redact"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ReconciliationPolicy(
	ctx context.Context, deviceID uuid.UUID,
) (bool, uint64, error) {
	var enabled bool
	var revision uint64
	err := s.DB.QueryRow(ctx, `SELECT antifraud_enabled,antifraud_policy_revision
		FROM devices WHERE id=$1 AND enabled AND purge_state='active'`, deviceID).
		Scan(&enabled, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, ErrNotFound
	}
	return enabled, revision, err
}

func (s *Store) EnqueueCDRReconciliationBuckets(
	ctx context.Context, deviceID uuid.UUID, revision uint64, buckets []time.Time,
) error {
	if len(buckets) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, bucket := range buckets {
		batch.Queue(`INSERT INTO custom_reconciliation_jobs
			(device_id,policy_revision,kind,bucket_start,generation)
			SELECT id,$2,'bucket',$3,1 FROM devices
			WHERE id=$1 AND antifraud_enabled AND antifraud_policy_revision=$2
			ON CONFLICT (device_id,policy_revision,kind,
				(COALESCE(bucket_start, '-infinity'::timestamptz)))
			DO UPDATE SET
				generation=custom_reconciliation_jobs.generation+1,
				status=CASE WHEN custom_reconciliation_jobs.status='running'
					THEN 'running' ELSE 'pending' END,
				next_attempt_at=LEAST(custom_reconciliation_jobs.next_attempt_at,now()),
				completed_at=NULL,last_error=NULL,updated_at=now()`,
			deviceID, revision, bucket.UTC().Truncate(time.Hour))
	}
	results := s.DB.SendBatch(ctx, batch)
	for range buckets {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return err
		}
	}
	return results.Close()
}

func (s *Store) ClaimReconciliationJob(
	ctx context.Context, workerID string, lease time.Duration,
) (reconciliation.Bucket, bool, error) {
	var job reconciliation.Bucket
	var start, cursor *time.Time
	var cursorID *uuid.UUID
	err := s.DB.QueryRow(ctx, `WITH eligible AS (
			SELECT DISTINCT ON (device_id) id
			FROM custom_reconciliation_jobs job
			WHERE ((status='pending' AND next_attempt_at<=now())
			   OR (status='running' AND job.lease_expires_at<now()))
			  AND NOT EXISTS (
				SELECT 1 FROM custom_reconciliation_device_leases lease
				WHERE lease.device_id=job.device_id AND lease.lease_expires_at>=now()
			  )
			ORDER BY device_id,updated_at,created_at
		), picked AS (
			SELECT job.id FROM custom_reconciliation_jobs job
			JOIN eligible USING (id)
			ORDER BY job.updated_at,job.created_at
			FOR UPDATE OF job SKIP LOCKED LIMIT 1
		), leased AS (
			INSERT INTO custom_reconciliation_device_leases
				(device_id,worker_id,lease_expires_at)
			SELECT job.device_id,$1,now()+$2::interval
			FROM custom_reconciliation_jobs job JOIN picked USING (id)
			ON CONFLICT (device_id) DO UPDATE SET
				worker_id=EXCLUDED.worker_id,lease_expires_at=EXCLUDED.lease_expires_at,
				updated_at=now()
			WHERE custom_reconciliation_device_leases.lease_expires_at<now()
			   OR custom_reconciliation_device_leases.worker_id=EXCLUDED.worker_id
			RETURNING device_id
		)
		UPDATE custom_reconciliation_jobs job
		SET status='running',worker_id=$1,lease_expires_at=now()+$2::interval,
			claimed_generation=generation,attempts=attempts+1,updated_at=now()
		FROM picked,leased WHERE job.id=picked.id AND leased.device_id=job.device_id
		RETURNING job.id,job.device_id,job.policy_revision,job.kind,job.bucket_start,
			job.cursor_event_at,job.cursor_record_id,job.generation`,
		workerID, lease.String()).Scan(
		&job.ID, &job.DeviceID, &job.PolicyRevision, &job.Kind, &start,
		&cursor, &cursorID, &job.Generation,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return reconciliation.Bucket{}, false, nil
	}
	if err != nil {
		return reconciliation.Bucket{}, false, err
	}
	if start != nil {
		job.Start = *start
	}
	if cursor != nil {
		job.CursorTime = *cursor
	}
	if cursorID != nil {
		job.CursorRecordID = *cursorID
	}
	job.WorkerID = workerID
	return job, true, nil
}

func (s *Store) AdvanceReconciliationDiscovery(
	ctx context.Context, job reconciliation.Bucket,
	nextTime time.Time, nextID uuid.UUID, hasMore bool,
) error {
	status := "completed"
	nextAttempt := time.Now().UTC()
	if hasMore {
		status = "pending"
	}
	_, err := s.DB.Exec(ctx, `UPDATE custom_reconciliation_jobs
		SET status=$2,cursor_event_at=NULLIF($3,'0001-01-01'::timestamptz),
			cursor_record_id=NULLIF($4,'00000000-0000-0000-0000-000000000000'::uuid),
			next_attempt_at=$5,lease_expires_at=NULL,worker_id=NULL,
			completed_at=CASE WHEN $2='completed' THEN now() ELSE NULL END,updated_at=now()
		WHERE id=$1 AND claimed_generation=$6`,
		job.ID, status, nextTime, nextID, nextAttempt, job.Generation)
	if err == nil {
		_, err = s.DB.Exec(ctx, `DELETE FROM custom_reconciliation_device_leases
			WHERE device_id=$1 AND worker_id=$2`, job.DeviceID, job.WorkerID)
	}
	return err
}

func (s *Store) CompleteReconciliationJob(
	ctx context.Context, job reconciliation.Bucket,
) error {
	_, err := s.DB.Exec(ctx, `UPDATE custom_reconciliation_jobs
		SET status=CASE WHEN generation=claimed_generation THEN 'completed' ELSE 'pending' END,
			completed_at=CASE WHEN generation=claimed_generation THEN now() ELSE NULL END,
			next_attempt_at=CASE WHEN generation=claimed_generation THEN next_attempt_at
				ELSE LEAST(next_attempt_at,now()) END,
			lease_expires_at=NULL,worker_id=NULL,updated_at=now()
		WHERE id=$1 AND claimed_generation=$2`, job.ID, job.Generation)
	if err == nil {
		_, err = s.DB.Exec(ctx, `DELETE FROM custom_reconciliation_device_leases
			WHERE device_id=$1 AND worker_id=$2`, job.DeviceID, job.WorkerID)
	}
	return err
}

func (s *Store) CommitReconciliation(
	ctx context.Context, job reconciliation.Bucket, deadline *time.Time,
	write func(context.Context) error,
) error {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx,
		`SELECT pg_advisory_lock(hashtextextended($1::text,$2))`,
		job.DeviceID.String(), customProjectionAdvisorySeed,
	); err != nil {
		return err
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx,
			`SELECT pg_advisory_unlock(hashtextextended($1::text,$2))`,
			job.DeviceID.String(), customProjectionAdvisorySeed)
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var enabled bool
	var revision uint64
	if err := tx.QueryRow(ctx, `SELECT antifraud_enabled,antifraud_policy_revision
		FROM devices WHERE id=$1 AND enabled AND purge_state='active' FOR UPDATE`,
		job.DeviceID).Scan(&enabled, &revision); err != nil {
		return err
	}
	if !enabled || revision != job.PolicyRevision {
		return errors.New("antifraud policy changed before reconciliation commit")
	}
	var status, owner string
	var claimedGeneration uint64
	var leaseValid bool
	if err := tx.QueryRow(ctx, `SELECT job.status,COALESCE(job.worker_id,''),
			job.claimed_generation,EXISTS (
				SELECT 1 FROM custom_reconciliation_device_leases lease
				WHERE lease.device_id=job.device_id AND lease.worker_id=$2
				  AND lease.lease_expires_at>=now()
			)
		FROM custom_reconciliation_jobs job WHERE job.id=$1 FOR UPDATE`,
		job.ID, job.WorkerID).Scan(
		&status, &owner, &claimedGeneration, &leaseValid,
	); err != nil {
		return err
	}
	if status != "running" || owner != job.WorkerID ||
		claimedGeneration != job.Generation || !leaseValid {
		return errors.New("reconciliation lease changed before commit")
	}
	if err := write(ctx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE custom_reconciliation_jobs
		SET status=CASE WHEN generation<>claimed_generation OR $3::timestamptz IS NOT NULL
				THEN 'pending' ELSE 'completed' END,
			completed_at=CASE WHEN generation=claimed_generation AND $3::timestamptz IS NULL
				THEN now() ELSE NULL END,
			next_attempt_at=CASE WHEN generation<>claimed_generation
				THEN LEAST(next_attempt_at,now())
				WHEN $3::timestamptz IS NOT NULL THEN $3
				ELSE next_attempt_at END,
			lease_expires_at=NULL,worker_id=NULL,updated_at=now()
		WHERE id=$1 AND claimed_generation=$2`, job.ID, job.Generation, deadline); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM custom_reconciliation_device_leases
		WHERE device_id=$1 AND worker_id=$2`, job.DeviceID, job.WorkerID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FailReconciliationJob(
	ctx context.Context, job reconciliation.Bucket, cause error, retryAfter time.Duration,
) error {
	_, err := s.DB.Exec(ctx, `UPDATE custom_reconciliation_jobs
		SET status=CASE WHEN attempts>=20 THEN 'failed' ELSE 'pending' END,
			last_error=$2,next_attempt_at=now()+$3::interval,
			lease_expires_at=NULL,worker_id=NULL,updated_at=now()
		WHERE id=$1 AND claimed_generation=$4`,
		job.ID, redact.Text(cause.Error()), retryAfter.String(), job.Generation)
	if err == nil {
		_, err = s.DB.Exec(ctx, `DELETE FROM custom_reconciliation_device_leases
			WHERE device_id=$1 AND worker_id=$2`, job.DeviceID, job.WorkerID)
	}
	return err
}

type ReconciliationQueueStats struct {
	Depth     uint64        `json:"depth"`
	OldestAge time.Duration `json:"oldestAge"`
	Failed    uint64        `json:"failed"`
}

func (s *Store) ReconciliationQueueStats(
	ctx context.Context,
) (ReconciliationQueueStats, error) {
	var stats ReconciliationQueueStats
	var oldestSeconds float64
	err := s.DB.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status IN ('pending','running')),
		COALESCE(EXTRACT(epoch FROM now()-min(created_at)
			FILTER (WHERE status IN ('pending','running'))),0),
		count(*) FILTER (WHERE status='failed')
		FROM custom_reconciliation_jobs`).Scan(
		&stats.Depth, &oldestSeconds, &stats.Failed,
	)
	stats.OldestAge = time.Duration(oldestSeconds * float64(time.Second))
	return stats, err
}
