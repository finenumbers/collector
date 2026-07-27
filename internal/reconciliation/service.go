package reconciliation

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Bucket struct {
	ID             uuid.UUID
	DeviceID       uuid.UUID
	Start          time.Time
	PolicyRevision uint64
	ProjectionSeq  uint64
	Kind           string
	CursorTime     time.Time
	CursorRecordID uuid.UUID
	Generation     uint64
	WorkerID       string
}

type Queue interface {
	ClaimReconciliationJob(context.Context, string, time.Duration) (Bucket, bool, error)
	EnqueueCDRReconciliationBuckets(context.Context, uuid.UUID, uint64, []time.Time) error
	AdvanceReconciliationDiscovery(context.Context, Bucket, time.Time, uuid.UUID, bool) error
	CompleteReconciliationJob(context.Context, Bucket) error
	FailReconciliationJob(context.Context, Bucket, error, time.Duration) error
	ReconciliationPolicy(context.Context, uuid.UUID) (bool, uint64, error)
	CommitReconciliation(context.Context, Bucket, *time.Time, func(context.Context) error) error
}

type Store interface {
	DiscoverCDRBuckets(
		context.Context, uuid.UUID, time.Time, uuid.UUID, int,
	) ([]time.Time, time.Time, uuid.UUID, bool, error)
	LoadReconciliationEvidence(context.Context, Bucket, time.Duration) ([]CDR, []Call, error)
	WriteReconciliationResult(context.Context, Bucket, Result, Config) error
}

type WorkerMetrics struct {
	Processed atomic.Uint64
	Failures  atomic.Uint64
}

type Worker struct {
	Store    Store
	Queue    Queue
	Config   Config
	Sleep    time.Duration
	Lease    time.Duration
	WorkerID string
	Metrics  *WorkerMetrics
	Now      func() time.Time
}

func (w *Worker) Run(ctx context.Context) error {
	if w.Store == nil || w.Queue == nil {
		return errors.New("reconciliation queue and store are required")
	}
	if w.Sleep <= 0 {
		w.Sleep = 5 * time.Second
	}
	if w.Lease <= 0 {
		w.Lease = 2 * time.Minute
	}
	if w.Now == nil {
		w.Now = func() time.Time { return time.Now().UTC() }
	}
	if w.Metrics == nil {
		w.Metrics = &WorkerMetrics{}
	}
	config := w.Config.normalized()
	for ctx.Err() == nil {
		bucket, ok, err := w.Queue.ClaimReconciliationJob(ctx, w.WorkerID, w.Lease)
		if err != nil {
			w.Metrics.Failures.Add(1)
			if !reconciliationSleep(ctx, w.Sleep) {
				break
			}
			continue
		}
		if !ok {
			if !reconciliationSleep(ctx, w.Sleep) {
				break
			}
			continue
		}
		enabled, revision, policyErr := w.Queue.ReconciliationPolicy(ctx, bucket.DeviceID)
		if policyErr != nil {
			w.Metrics.Failures.Add(1)
			_ = w.Queue.FailReconciliationJob(ctx, bucket, policyErr, w.Sleep)
			continue
		}
		if !enabled || revision != bucket.PolicyRevision {
			_ = w.Queue.CompleteReconciliationJob(ctx, bucket)
			continue
		}
		if bucket.Kind == "discover" {
			var buckets []time.Time
			var nextTime time.Time
			var nextID uuid.UUID
			var hasMore bool
			buckets, nextTime, nextID, hasMore, err = w.Store.DiscoverCDRBuckets(
				ctx, bucket.DeviceID, bucket.CursorTime, bucket.CursorRecordID, 256,
			)
			if err == nil {
				err = w.Queue.EnqueueCDRReconciliationBuckets(
					ctx, bucket.DeviceID, bucket.PolicyRevision, buckets,
				)
			}
			if err == nil {
				err = w.Queue.AdvanceReconciliationDiscovery(
					ctx, bucket, nextTime, nextID, hasMore,
				)
			}
		} else {
			var cdrs []CDR
			var calls []Call
			cdrs, calls, err = w.Store.LoadReconciliationEvidence(
				ctx, bucket, config.RetryHorizon,
			)
			if err == nil {
				result := Reconcile(config, w.Now(), cdrs, calls)
				err = w.Queue.CommitReconciliation(
					ctx, bucket, result.NextDeadline, func(commitCtx context.Context) error {
						return w.Store.WriteReconciliationResult(
							commitCtx, bucket, result, config,
						)
					},
				)
			}
		}
		if err != nil {
			w.Metrics.Failures.Add(1)
			_ = w.Queue.FailReconciliationJob(ctx, bucket, err, w.Sleep)
			continue
		}
		w.Metrics.Processed.Add(1)
	}
	return nil
}

func reconciliationSleep(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
