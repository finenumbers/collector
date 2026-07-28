package store

import (
	"context"
	"errors"
	"time"

	"collector/internal/customprojection"
	"collector/internal/redact"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) CustomAntifraudPolicy(
	ctx context.Context, deviceID uuid.UUID,
) (customprojection.Policy, error) {
	var policy customprojection.Policy
	policy.DeviceID = deviceID
	err := s.DB.QueryRow(ctx, `SELECT antifraud_enabled,antifraud_policy_revision,active_timezone
		FROM devices WHERE id=$1 AND enabled AND purge_state='active'`, deviceID).
		Scan(&policy.Enabled, &policy.Revision, &policy.Timezone)
	if errors.Is(err, pgx.ErrNoRows) {
		return customprojection.Policy{}, ErrNotFound
	}
	return policy, err
}

func (s *Store) CustomAntifraudReady(
	ctx context.Context, deviceID uuid.UUID,
) (bool, error) {
	var ready bool
	err := s.DB.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM custom_projection_watermarks watermark
		JOIN devices device ON device.id=watermark.device_id
		WHERE device.id=$1 AND device.antifraud_enabled
		  AND watermark.policy_revision=device.antifraud_policy_revision
		  AND watermark.state='active'
	)`, deviceID).Scan(&ready)
	return ready, err
}

func (s *Store) SetCustomProjectionGlobalEnabled(
	ctx context.Context, enabled bool, lookback time.Duration,
) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if !enabled {
		for _, table := range []string{"custom_projection_jobs", "custom_reconciliation_jobs"} {
			if _, err := tx.Exec(ctx, `UPDATE `+table+`
				SET status='cancelled',lease_expires_at=NULL,worker_id=NULL,
					completed_at=now(),updated_at=now()
				WHERE status IN ('pending','running')`); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	if lookback <= 0 {
		lookback = 24 * time.Hour
	}
	cursorStart := time.Now().UTC().Add(-lookback)
	// Cancel only historical buckets that would replay days of Syslog.
	if _, err := tx.Exec(ctx, `UPDATE custom_projection_jobs
		SET status='cancelled',lease_expires_at=NULL,worker_id=NULL,
			completed_at=now(),updated_at=now()
		WHERE kind='bucket' AND status IN ('pending','running') AND bucket_start < $1`,
		cursorStart); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE custom_reconciliation_jobs
		SET status='cancelled',lease_expires_at=NULL,worker_id=NULL,
			completed_at=now(),updated_at=now()
		WHERE kind='bucket' AND status IN ('pending','running') AND bucket_start < $1`,
		cursorStart); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO custom_projection_jobs
		(device_id,policy_revision,kind,cursor_received_at,cursor_event_id,generation)
		SELECT id,antifraud_policy_revision,'discover',$1,
			'00000000-0000-0000-0000-000000000000',1 FROM devices
		WHERE antifraud_enabled AND enabled AND purge_state='active'
		ON CONFLICT (device_id,policy_revision,kind,
			(COALESCE(bucket_start, '-infinity'::timestamptz)))
		DO UPDATE SET
			status=CASE
				WHEN custom_projection_jobs.status IN ('cancelled','failed') THEN 'pending'
				ELSE custom_projection_jobs.status
			END,
			generation=CASE
				WHEN custom_projection_jobs.status IN ('cancelled','failed')
					THEN custom_projection_jobs.generation+1
				ELSE custom_projection_jobs.generation
			END,
			projection_seq=CASE
				WHEN custom_projection_jobs.status IN ('cancelled','failed')
					THEN nextval('custom_projection_seq')
				ELSE custom_projection_jobs.projection_seq
			END,
			cursor_received_at=CASE
				WHEN custom_projection_jobs.cursor_received_at IS NULL
					OR custom_projection_jobs.cursor_received_at < $1
					OR custom_projection_jobs.status IN ('cancelled','failed')
				THEN $1 ELSE custom_projection_jobs.cursor_received_at
			END,
			cursor_event_id=CASE
				WHEN custom_projection_jobs.cursor_received_at IS NULL
					OR custom_projection_jobs.cursor_received_at < $1
					OR custom_projection_jobs.status IN ('cancelled','failed')
				THEN '00000000-0000-0000-0000-000000000000'
				ELSE custom_projection_jobs.cursor_event_id
			END,
			next_attempt_at=LEAST(custom_projection_jobs.next_attempt_at,now()),
			completed_at=NULL,last_error=NULL,updated_at=now()`,
		cursorStart); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO custom_reconciliation_jobs
		(device_id,policy_revision,kind,cursor_event_at,cursor_record_id,generation)
		SELECT id,antifraud_policy_revision,'discover',$1,
			'00000000-0000-0000-0000-000000000000',1 FROM devices
		WHERE antifraud_enabled AND enabled AND purge_state='active'
		ON CONFLICT (device_id,policy_revision,kind,
			(COALESCE(bucket_start, '-infinity'::timestamptz)))
		DO UPDATE SET
			status=CASE
				WHEN custom_reconciliation_jobs.status IN ('cancelled','failed') THEN 'pending'
				ELSE custom_reconciliation_jobs.status
			END,
			generation=CASE
				WHEN custom_reconciliation_jobs.status IN ('cancelled','failed')
					THEN custom_reconciliation_jobs.generation+1
				ELSE custom_reconciliation_jobs.generation
			END,
			cursor_event_at=CASE
				WHEN custom_reconciliation_jobs.cursor_event_at IS NULL
					OR custom_reconciliation_jobs.cursor_event_at < $1
					OR custom_reconciliation_jobs.status IN ('cancelled','failed')
				THEN $1 ELSE custom_reconciliation_jobs.cursor_event_at
			END,
			cursor_record_id=CASE
				WHEN custom_reconciliation_jobs.cursor_event_at IS NULL
					OR custom_reconciliation_jobs.cursor_event_at < $1
					OR custom_reconciliation_jobs.status IN ('cancelled','failed')
				THEN '00000000-0000-0000-0000-000000000000'
				ELSE custom_reconciliation_jobs.cursor_record_id
			END,
			next_attempt_at=LEAST(custom_reconciliation_jobs.next_attempt_at,now()),
			completed_at=NULL,last_error=NULL,updated_at=now()`,
		cursorStart); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) EnqueueCustomProjectionBuckets(
	ctx context.Context, deviceID uuid.UUID, revision uint64, buckets []time.Time,
) error {
	if len(buckets) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, bucket := range buckets {
		batch.Queue(`INSERT INTO custom_projection_jobs
			(device_id,policy_revision,kind,bucket_start,generation)
			SELECT id,$2,'bucket',$3,1 FROM devices
			WHERE id=$1 AND antifraud_enabled AND antifraud_policy_revision=$2
			ON CONFLICT (device_id,policy_revision,kind,
				(COALESCE(bucket_start, '-infinity'::timestamptz)))
			DO UPDATE SET
				generation=custom_projection_jobs.generation+1,
				projection_seq=nextval('custom_projection_seq'),
				cutoff_at=NULL,
				status=CASE WHEN custom_projection_jobs.status='running'
					THEN 'running' ELSE 'pending' END,
				next_attempt_at=LEAST(custom_projection_jobs.next_attempt_at,now()),
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

func (s *Store) ClaimCustomProjectionJob(
	ctx context.Context, workerID string, lease time.Duration,
) (customprojection.Job, bool, error) {
	var job customprojection.Job
	var bucket, cursorTime, cutoff *time.Time
	var cursorID *uuid.UUID
	err := s.DB.QueryRow(ctx, `WITH eligible AS (
			SELECT DISTINCT ON (device_id) id
			FROM custom_projection_jobs job
			WHERE ((status='pending' AND next_attempt_at<=now())
			   OR (status='running' AND job.lease_expires_at<now()))
			  AND NOT EXISTS (
				SELECT 1 FROM custom_projection_device_leases lease
				WHERE lease.device_id=job.device_id AND lease.lease_expires_at>=now()
			  )
			ORDER BY device_id,updated_at,created_at
		), picked AS (
			SELECT job.id FROM custom_projection_jobs job
			JOIN eligible USING (id)
			LEFT JOIN custom_projection_watermarks watermark
				ON watermark.device_id=job.device_id
			ORDER BY COALESCE(EXTRACT(epoch FROM now()-watermark.watermark_received_at), 1e12) DESC,
				job.updated_at,job.created_at
			FOR UPDATE OF job SKIP LOCKED LIMIT 1
		), leased AS (
			INSERT INTO custom_projection_device_leases
				(device_id,worker_id,lease_expires_at)
			SELECT job.device_id,$1,now()+$2::interval
			FROM custom_projection_jobs job JOIN picked USING (id)
			ON CONFLICT (device_id) DO UPDATE SET
				worker_id=EXCLUDED.worker_id,lease_expires_at=EXCLUDED.lease_expires_at,
				updated_at=now()
			WHERE custom_projection_device_leases.lease_expires_at<now()
			   OR custom_projection_device_leases.worker_id=EXCLUDED.worker_id
			RETURNING device_id
		)
		UPDATE custom_projection_jobs job
		SET status='running',worker_id=$1,lease_expires_at=now()+$2::interval,
			claimed_generation=generation,attempts=attempts+1,updated_at=now()
		FROM picked,leased WHERE job.id=picked.id AND leased.device_id=job.device_id
		RETURNING job.id,job.device_id,job.policy_revision,job.projection_seq,job.kind,
			job.bucket_start,job.cursor_received_at,job.cursor_event_id,
			job.generation,job.cutoff_at`,
		workerID, lease.String(),
	).Scan(
		&job.ID, &job.DeviceID, &job.PolicyRevision, &job.ProjectionSeq, &job.Kind,
		&bucket, &cursorTime, &cursorID, &job.Generation, &cutoff,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return customprojection.Job{}, false, nil
	}
	if err != nil {
		return customprojection.Job{}, false, err
	}
	if bucket != nil {
		job.BucketStart = *bucket
	}
	if cursorTime != nil {
		job.CursorTime = *cursorTime
	}
	if cursorID != nil {
		job.CursorEventID = *cursorID
	}
	if cutoff != nil {
		job.CutoffAt = *cutoff
	}
	job.WorkerID = workerID
	return job, true, nil
}

func (s *Store) releaseCustomProjectionDeviceLease(
	ctx context.Context, deviceID uuid.UUID, workerID string,
) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM custom_projection_device_leases
		WHERE device_id=$1 AND worker_id=$2`, deviceID, workerID)
	return err
}

func (s *Store) AdvanceCustomProjectionDiscovery(
	ctx context.Context, job customprojection.Job, discovery customprojection.Discovery,
) error {
	nextTime, nextID := discovery.NextTime, discovery.NextEventID
	if nextTime.IsZero() {
		nextTime, nextID = job.CursorTime, job.CursorEventID
	}
	nextAttempt := time.Now().UTC().Add(2 * time.Second)
	if discovery.HasMore {
		nextAttempt = time.Now().UTC()
	}
	_, err := s.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET status='pending',cursor_received_at=NULLIF($2,'0001-01-01'::timestamptz),
			cursor_event_id=NULLIF($3,'00000000-0000-0000-0000-000000000000'::uuid),
			next_attempt_at=$4,lease_expires_at=NULL,worker_id=NULL,completed_at=NULL,updated_at=now()
		WHERE id=$1 AND policy_revision=$5`,
		job.ID, nextTime, nextID, nextAttempt, job.PolicyRevision)
	if err == nil {
		err = s.releaseCustomProjectionDeviceLease(ctx, job.DeviceID, job.WorkerID)
	}
	return err
}

func (s *Store) CompleteCustomProjectionJob(
	ctx context.Context, job customprojection.Job, snapshot customprojection.Snapshot,
) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if snapshot.ID != uuid.Nil {
		tag, err := tx.Exec(ctx, `UPDATE custom_projection_watermarks watermark
			SET previous_snapshot_id=active_snapshot_id,active_snapshot_id=$3,
				watermark_received_at=NULLIF($4,'0001-01-01'::timestamptz),
				watermark_event_id=NULLIF($5,'00000000-0000-0000-0000-000000000000'::uuid),
				projection_seq=$6,state='active',updated_at=now()
			FROM devices device
			WHERE watermark.device_id=$1 AND device.id=$1
			  AND device.antifraud_enabled AND device.antifraud_policy_revision=$2`,
			job.DeviceID, job.PolicyRevision, snapshot.ID, snapshot.WatermarkTime,
			snapshot.WatermarkID, snapshot.ProjectionSeq)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("policy changed while completing projection")
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE custom_projection_jobs
		SET status=CASE WHEN generation=claimed_generation THEN 'completed' ELSE 'pending' END,
			completed_at=CASE WHEN generation=claimed_generation THEN now() ELSE NULL END,
			next_attempt_at=CASE WHEN generation=claimed_generation THEN next_attempt_at
				ELSE LEAST(next_attempt_at,now()) END,
			lease_expires_at=NULL,worker_id=NULL,updated_at=now()
		WHERE id=$1`, job.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM custom_projection_device_leases
		WHERE device_id=$1 AND worker_id=$2`, job.DeviceID, job.WorkerID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ScheduleCustomProjectionDeadline(
	ctx context.Context, job customprojection.Job, deadline time.Time,
) error {
	_, err := s.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET generation=generation+1,projection_seq=nextval('custom_projection_seq'),
			cutoff_at=$2,next_attempt_at=CASE WHEN generation=claimed_generation
				THEN $2 ELSE LEAST(next_attempt_at,$2) END,
			status=CASE WHEN status='running' THEN 'running' ELSE 'pending' END,
			completed_at=NULL,updated_at=now()
		WHERE id=$1 AND policy_revision=$3`, job.ID, deadline.UTC(), job.PolicyRevision)
	return err
}

const customProjectionAdvisorySeed int64 = 0x435553544f4d

func (s *Store) CutoverCustomProjection(
	ctx context.Context,
	job customprojection.Job,
	snapshot customprojection.Snapshot,
	activate func(context.Context) error,
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
		return errors.New("antifraud policy changed before snapshot cutover")
	}
	var status, owner string
	var claimedGeneration uint64
	if err := tx.QueryRow(ctx, `SELECT status,COALESCE(worker_id,''),claimed_generation
		FROM custom_projection_jobs WHERE id=$1 FOR UPDATE`, job.ID).
		Scan(&status, &owner, &claimedGeneration); err != nil {
		return err
	}
	if status != "running" || owner != job.WorkerID || claimedGeneration != job.Generation {
		return errors.New("projection lease changed before snapshot cutover")
	}
	if err := activate(ctx); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE custom_projection_watermarks
		SET previous_snapshot_id=active_snapshot_id,active_snapshot_id=$3,
			watermark_received_at=CASE
				WHEN $4::timestamptz IS NULL OR $4::timestamptz='0001-01-01'::timestamptz
					THEN watermark_received_at
				WHEN watermark_received_at IS NULL OR $4::timestamptz>=watermark_received_at
					THEN $4::timestamptz
				ELSE watermark_received_at
			END,
			watermark_event_id=CASE
				WHEN $4::timestamptz IS NULL OR $4::timestamptz='0001-01-01'::timestamptz
					THEN watermark_event_id
				WHEN watermark_received_at IS NULL OR $4::timestamptz>watermark_received_at
					THEN NULLIF($5,'00000000-0000-0000-0000-000000000000'::uuid)
				WHEN $4::timestamptz=watermark_received_at
					THEN COALESCE(NULLIF($5,'00000000-0000-0000-0000-000000000000'::uuid), watermark_event_id)
				ELSE watermark_event_id
			END,
			projection_seq=$6,state='active',updated_at=now()
		WHERE device_id=$1 AND policy_revision=$2`,
		job.DeviceID, job.PolicyRevision, snapshot.ID, snapshot.WatermarkTime,
		snapshot.WatermarkID, snapshot.ProjectionSeq)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("projection watermark compare-and-swap failed")
	}
	if _, err := tx.Exec(ctx, `UPDATE custom_projection_jobs
		SET status=CASE WHEN generation=claimed_generation THEN 'completed' ELSE 'pending' END,
			completed_at=CASE WHEN generation=claimed_generation THEN now() ELSE NULL END,
			next_attempt_at=CASE WHEN generation=claimed_generation THEN next_attempt_at
				ELSE LEAST(next_attempt_at,now()) END,
			lease_expires_at=NULL,worker_id=NULL,updated_at=now()
		WHERE id=$1 AND claimed_generation=$2`, job.ID, job.Generation); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM custom_projection_device_leases
		WHERE device_id=$1 AND worker_id=$2`, job.DeviceID, job.WorkerID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FailCustomProjectionJob(
	ctx context.Context, job customprojection.Job, cause error, retryAfter time.Duration,
) error {
	_, err := s.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET status=CASE
				WHEN kind='discover' THEN 'pending'
				WHEN attempts>=20 THEN 'failed'
				ELSE 'pending'
			END,
			last_error=$2,next_attempt_at=now()+$3::interval,
			lease_expires_at=NULL,worker_id=NULL,updated_at=now()
		WHERE id=$1`, job.ID, redact.Text(cause.Error()), retryAfter.String())
	if err == nil {
		err = s.releaseCustomProjectionDeviceLease(ctx, job.DeviceID, job.WorkerID)
	}
	return err
}

func (s *Store) RequeueFailedProjectionJobs(
	ctx context.Context, deviceID uuid.UUID,
) (int64, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET status='pending',attempts=0,next_attempt_at=now(),last_error=NULL,
			lease_expires_at=NULL,worker_id=NULL,completed_at=NULL,updated_at=now()
		WHERE device_id=$1 AND status='failed'`, deviceID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) RequeueFailedOverflowProjectionJobs(ctx context.Context) (int64, error) {
	tag, err := s.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET status='pending',attempts=0,next_attempt_at=now(),last_error=NULL,
			lease_expires_at=NULL,worker_id=NULL,completed_at=NULL,updated_at=now()
		WHERE status='failed'
		  AND (last_error ILIKE '%exceeds%events%'
			OR last_error ILIKE '%memory bound%'
			OR last_error ILIKE '%memory limit exceeded%'
			OR last_error ILIKE '%query was cancelled%'
			OR last_error ILIKE '%timeout exceeded%'
			OR last_error ILIKE '%context deadline exceeded%')`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

type CustomProjectionQueueStats struct {
	Depth       uint64        `json:"depth"`
	OldestAge   time.Duration `json:"oldestAge"`
	Failed      uint64        `json:"failed"`
	Backfilling uint64        `json:"backfilling"`
}

type CustomProjectionDeviceStats struct {
	DeviceID            uuid.UUID     `json:"deviceId"`
	Name                string        `json:"name"`
	Depth               uint64        `json:"depth"`
	Failed              uint64        `json:"failed"`
	Backfilling         uint64        `json:"backfilling"`
	OldestAge           time.Duration `json:"oldestAge"`
	WatermarkState      string        `json:"watermarkState"`
	WatermarkLagSeconds int64         `json:"watermarkLagSeconds"`
	LastError           string        `json:"lastError,omitempty"`
}

func (s *Store) CustomProjectionQueueStats(
	ctx context.Context,
) (CustomProjectionQueueStats, error) {
	var stats CustomProjectionQueueStats
	var oldestSeconds float64
	err := s.DB.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status IN ('pending','running')),
		COALESCE(EXTRACT(epoch FROM now()-min(created_at)
			FILTER (WHERE status IN ('pending','running'))),0),
		count(*) FILTER (WHERE status='failed'),
		count(*) FILTER (WHERE kind='discover' AND status IN ('pending','running'))
		FROM custom_projection_jobs`).
		Scan(&stats.Depth, &oldestSeconds, &stats.Failed, &stats.Backfilling)
	stats.OldestAge = time.Duration(oldestSeconds * float64(time.Second))
	return stats, err
}

func (s *Store) CustomProjectionDeviceStats(
	ctx context.Context,
) ([]CustomProjectionDeviceStats, error) {
	rows, err := s.DB.Query(ctx, `SELECT device.id,device.name,
		count(job.id) FILTER (WHERE job.status IN ('pending','running')),
		count(job.id) FILTER (WHERE job.status='failed'),
		count(job.id) FILTER (WHERE job.kind='discover' AND job.status IN ('pending','running')),
		COALESCE(EXTRACT(epoch FROM now()-min(job.created_at)
			FILTER (WHERE job.status IN ('pending','running'))),0),
		COALESCE(watermark.state,'disabled'),
		GREATEST(0,COALESCE(EXTRACT(epoch FROM now()-watermark.watermark_received_at),0))::bigint,
		COALESCE((
			SELECT j.last_error FROM custom_projection_jobs j
			WHERE j.device_id=device.id AND j.last_error IS NOT NULL AND j.last_error<>''
			ORDER BY j.updated_at DESC LIMIT 1
		),'')
		FROM devices device
		LEFT JOIN custom_projection_jobs job ON job.device_id=device.id
		LEFT JOIN custom_projection_watermarks watermark ON watermark.device_id=device.id
		WHERE device.antifraud_enabled AND device.enabled AND device.purge_state='active'
		GROUP BY device.id,device.name,watermark.state,watermark.watermark_received_at
		ORDER BY GREATEST(0,COALESCE(EXTRACT(epoch FROM now()-watermark.watermark_received_at),0)) DESC,
			device.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]CustomProjectionDeviceStats, 0)
	for rows.Next() {
		var item CustomProjectionDeviceStats
		var oldestSeconds float64
		if err := rows.Scan(
			&item.DeviceID, &item.Name, &item.Depth, &item.Failed, &item.Backfilling,
			&oldestSeconds, &item.WatermarkState, &item.WatermarkLagSeconds, &item.LastError,
		); err != nil {
			return nil, err
		}
		item.OldestAge = time.Duration(oldestSeconds * float64(time.Second))
		result = append(result, item)
	}
	return result, rows.Err()
}
