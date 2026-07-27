package store

import (
	"context"
	"errors"
	"time"

	"collector/internal/redact"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type VoipmonitorJob struct {
	ID             uuid.UUID
	DeviceID       uuid.UUID
	PolicyRevision uint64
	Kind           string
	BucketStart    *time.Time
	Generation     int64
}

func (s *Store) VoipmonitorPolicy(
	ctx context.Context, deviceID uuid.UUID,
) (bool, uint64, error) {
	var enabled bool
	var revision uint64
	err := s.DB.QueryRow(ctx, `SELECT voipmonitor_enabled,voipmonitor_policy_revision
		FROM devices WHERE id=$1 AND enabled AND purge_state='active'`, deviceID).
		Scan(&enabled, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, 0, ErrNotFound
	}
	return enabled, revision, err
}

func (s *Store) EnqueueVoipmonitorBuckets(
	ctx context.Context, deviceID uuid.UUID, revision uint64, buckets []time.Time,
) error {
	if len(buckets) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, bucket := range buckets {
		batch.Queue(`INSERT INTO voipmonitor_match_jobs
			(device_id,policy_revision,kind,bucket_start,generation)
			SELECT id,$2,'bucket',$3,1 FROM devices
			WHERE id=$1 AND voipmonitor_enabled AND voipmonitor_policy_revision=$2
			ON CONFLICT (device_id,policy_revision,kind,
				(COALESCE(bucket_start, '-infinity'::timestamptz)))
			DO UPDATE SET
				generation=voipmonitor_match_jobs.generation+1,
				status=CASE WHEN voipmonitor_match_jobs.status='running'
					THEN 'running' ELSE 'pending' END,
				next_attempt_at=LEAST(voipmonitor_match_jobs.next_attempt_at,now()),
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

func (s *Store) ClaimVoipmonitorJob(
	ctx context.Context, workerID string, lease time.Duration,
) (VoipmonitorJob, bool, error) {
	var job VoipmonitorJob
	var bucket *time.Time
	err := s.DB.QueryRow(ctx, `WITH eligible AS (
			SELECT DISTINCT ON (device_id) id
			FROM voipmonitor_match_jobs job
			WHERE ((status='pending' AND next_attempt_at<=now())
			   OR (status='running' AND job.lease_expires_at<now()))
			  AND NOT EXISTS (
				SELECT 1 FROM voipmonitor_device_leases lease
				WHERE lease.device_id=job.device_id AND lease.lease_expires_at>=now()
			  )
			ORDER BY device_id,updated_at,created_at
		), picked AS (
			SELECT job.id FROM voipmonitor_match_jobs job
			JOIN eligible USING (id)
			ORDER BY job.updated_at,job.created_at
			FOR UPDATE OF job SKIP LOCKED LIMIT 1
		), leased AS (
			INSERT INTO voipmonitor_device_leases
				(device_id,worker_id,lease_expires_at)
			SELECT job.device_id,$1,now()+$2::interval
			FROM voipmonitor_match_jobs job JOIN picked USING (id)
			ON CONFLICT (device_id) DO UPDATE SET
				worker_id=EXCLUDED.worker_id,lease_expires_at=EXCLUDED.lease_expires_at,
				updated_at=now()
			WHERE voipmonitor_device_leases.lease_expires_at<now()
			   OR voipmonitor_device_leases.worker_id=EXCLUDED.worker_id
			RETURNING device_id
		)
		UPDATE voipmonitor_match_jobs job
		SET status='running',worker_id=$1,lease_expires_at=now()+$2::interval,
			claimed_generation=generation,attempts=attempts+1,updated_at=now()
		FROM picked,leased WHERE job.id=picked.id AND leased.device_id=job.device_id
		RETURNING job.id,job.device_id,job.policy_revision,job.kind,job.bucket_start,job.generation`,
		workerID, lease.String()).Scan(
		&job.ID, &job.DeviceID, &job.PolicyRevision, &job.Kind, &bucket, &job.Generation,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return VoipmonitorJob{}, false, nil
	}
	if err != nil {
		return VoipmonitorJob{}, false, err
	}
	job.BucketStart = bucket
	return job, true, nil
}

func (s *Store) CompleteVoipmonitorJob(ctx context.Context, job VoipmonitorJob) error {
	_, err := s.DB.Exec(ctx, `UPDATE voipmonitor_match_jobs
		SET status=CASE WHEN claimed_generation=generation THEN 'completed' ELSE 'pending' END,
			lease_expires_at=NULL,worker_id=NULL,completed_at=now(),last_error=NULL,updated_at=now()
		WHERE id=$1`, job.ID)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `DELETE FROM voipmonitor_device_leases WHERE device_id=$1`, job.DeviceID)
	return err
}

func (s *Store) FailVoipmonitorJob(ctx context.Context, job VoipmonitorJob, cause error) error {
	_, err := s.DB.Exec(ctx, `UPDATE voipmonitor_match_jobs
		SET status=CASE WHEN attempts>=20 THEN 'failed' ELSE 'pending' END,
			next_attempt_at=now()+interval '30 seconds'*(LEAST(attempts,10)),
			lease_expires_at=NULL,worker_id=NULL,last_error=$2,updated_at=now(),
			completed_at=CASE WHEN attempts>=20 THEN now() ELSE NULL END
		WHERE id=$1`, job.ID, redact.Text(cause.Error()))
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(ctx, `DELETE FROM voipmonitor_device_leases WHERE device_id=$1`, job.DeviceID)
	return err
}

func (s *Store) EnsureVoipmonitorDiscover(ctx context.Context, deviceID uuid.UUID, revision uint64) error {
	_, err := s.DB.Exec(ctx, `INSERT INTO voipmonitor_match_jobs
		(device_id,policy_revision,kind,generation)
		VALUES ($1,$2,'discover',1)
		ON CONFLICT (device_id,policy_revision,kind,
			(COALESCE(bucket_start, '-infinity'::timestamptz)))
		DO UPDATE SET
			generation=voipmonitor_match_jobs.generation+1,
			status='pending',next_attempt_at=now(),completed_at=NULL,last_error=NULL,updated_at=now()`,
		deviceID, revision)
	return err
}
