package retention

import (
	"context"
	"errors"
	"fmt"
	"time"

	"collector/internal/store"
)

type policyStore interface {
	TryRetentionLock(context.Context) (func(), bool, error)
	CleanupExpiredSessions(context.Context) error
	DueRetentionPolicies(context.Context) ([]store.RetentionPolicy, error)
	FailRetentionPolicy(context.Context, string, time.Time, error) error
	CompleteRetentionPolicy(context.Context, string, int, time.Time) error
}

type analyticsRetention interface {
	ApplyRetention(context.Context, string, int) error
}

type archiveRetention interface {
	ApplyCDRRetention(context.Context, int) error
}

type Reconciler struct {
	Store     policyStore
	Analytics analyticsRetention
	Archive   archiveRetention
}

func (r *Reconciler) Run(ctx context.Context) error {
	return r.run(ctx, false)
}

func (r *Reconciler) RunNow(ctx context.Context) error {
	return r.run(ctx, true)
}

func (r *Reconciler) run(ctx context.Context, waitForLock bool) error {
	var release func()
	for {
		acquiredRelease, acquired, err := r.Store.TryRetentionLock(ctx)
		if err != nil {
			return err
		}
		if acquired {
			release = acquiredRelease
			break
		}
		if !waitForLock {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer release()
	if err := r.Store.CleanupExpiredSessions(ctx); err != nil {
		return fmt.Errorf("cleanup expired sessions: %w", err)
	}
	policies, err := r.Store.DueRetentionPolicies(ctx)
	if err != nil {
		return err
	}
	var result error
	for _, policy := range policies {
		if policy.PendingDays == nil {
			continue
		}
		days := *policy.PendingDays
		var applyErr error
		if policy.PolicyClass == "raw_cdr_archive" {
			if r.Archive == nil {
				applyErr = errors.New("MinIO archive is unavailable")
			} else {
				applyErr = r.Archive.ApplyCDRRetention(ctx, days)
			}
		} else {
			applyErr = r.Analytics.ApplyRetention(ctx, policy.PolicyClass, days)
		}
		if applyErr != nil {
			recordErr := r.Store.FailRetentionPolicy(
				ctx, policy.PolicyClass, policy.UpdatedAt, applyErr,
			)
			result = errors.Join(result, applyErr)
			result = errors.Join(result, recordErr)
			continue
		}
		if err := r.Store.CompleteRetentionPolicy(
			ctx, policy.PolicyClass, days, policy.UpdatedAt,
		); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
