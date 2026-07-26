package retention

import (
	"context"
	"errors"
	"fmt"

	"collector/internal/analytics"
	"collector/internal/archive"
	"collector/internal/store"
)

type Reconciler struct {
	Store     *store.Store
	Analytics *analytics.Client
	Archive   *archive.Archive
}

func (r *Reconciler) Run(ctx context.Context) error {
	release, acquired, err := r.Store.TryRetentionLock(ctx)
	if err != nil || !acquired {
		return err
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
