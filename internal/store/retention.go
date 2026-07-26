package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const retentionLockKey int64 = 84201973

type RetentionPolicy struct {
	PolicyClass   string     `json:"policyClass"`
	ActiveDays    int        `json:"activeDays"`
	PendingDays   *int       `json:"pendingDays"`
	EffectiveAt   *time.Time `json:"effectiveAt"`
	UpdatedBy     *string    `json:"updatedBy"`
	LastAppliedAt *time.Time `json:"lastAppliedAt"`
	LastError     *string    `json:"lastError"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

func (s *Store) ListRetentionPolicies(ctx context.Context) ([]RetentionPolicy, error) {
	rows, err := s.DB.Query(ctx, `SELECT policy_class,active_days,pending_days,effective_at,
		updated_by::text,last_applied_at,last_error,updated_at
		FROM retention_policies ORDER BY policy_class`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]RetentionPolicy, 0, 4)
	for rows.Next() {
		var item RetentionPolicy
		if err := rows.Scan(&item.PolicyClass, &item.ActiveDays, &item.PendingDays,
			&item.EffectiveAt, &item.UpdatedBy, &item.LastAppliedAt, &item.LastError,
			&item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateRetentionPolicy(
	ctx context.Context, class string, days int, cancel bool,
	actor User, remoteIP string,
) (RetentionPolicy, error) {
	if !validRetentionClass(class) {
		return RetentionPolicy{}, errors.New("invalid retention policy class")
	}
	if !cancel && (days < 7 || days > 1095) {
		return RetentionPolicy{}, errors.New("retention days must be between 7 and 1095")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return RetentionPolicy{}, err
	}
	defer tx.Rollback(ctx)
	var active int
	if err := tx.QueryRow(ctx, `SELECT active_days FROM retention_policies
		WHERE policy_class=$1 FOR UPDATE`, class).Scan(&active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RetentionPolicy{}, ErrNotFound
		}
		return RetentionPolicy{}, err
	}
	action := "retention_update"
	details := map[string]any{"policyClass": class}
	if cancel {
		action = "retention_cancel"
		_, err = tx.Exec(ctx, `UPDATE retention_policies SET pending_days=NULL,effective_at=NULL,
			updated_by=$2,last_error=NULL,updated_at=now() WHERE policy_class=$1`, class, actor.ID)
	} else {
		effective, scheduleErr := retentionEffectiveAt(time.Now().UTC(), days)
		if scheduleErr != nil {
			return RetentionPolicy{}, scheduleErr
		}
		details["days"] = days
		details["previousDays"] = active
		details["effectiveAt"] = effective
		_, err = tx.Exec(ctx, `UPDATE retention_policies SET pending_days=$2,effective_at=$3,
			updated_by=$4,last_error=NULL,updated_at=now() WHERE policy_class=$1`,
			class, days, effective, actor.ID)
	}
	if err != nil {
		return RetentionPolicy{}, err
	}
	encoded, _ := json.Marshal(details)
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(actor_id,action,resource_type,resource_id,remote_ip,details)
		VALUES($1,$2,'retention_policy',$3,$4,$5)`,
		actor.ID, action, class, nullableIP(remoteIP), encoded); err != nil {
		return RetentionPolicy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RetentionPolicy{}, err
	}
	items, err := s.ListRetentionPolicies(ctx)
	if err != nil {
		return RetentionPolicy{}, err
	}
	for _, item := range items {
		if item.PolicyClass == class {
			return item, nil
		}
	}
	return RetentionPolicy{}, ErrNotFound
}

func retentionEffectiveAt(now time.Time, days int) (time.Time, error) {
	if days < 7 || days > 1095 {
		return time.Time{}, errors.New("retention days must be between 7 and 1095")
	}
	return now, nil
}

func validRetentionClass(class string) bool {
	switch class {
	case "syslog", "cdr", "softswitch_cdr", "derived", "raw_cdr_archive":
		return true
	default:
		return false
	}
}

func (s *Store) TryRetentionLock(ctx context.Context) (func(), bool, error) {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var acquired bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, retentionLockKey).
		Scan(&acquired); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !acquired {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, retentionLockKey)
		conn.Release()
	}, true, nil
}

func (s *Store) DueRetentionPolicies(ctx context.Context) ([]RetentionPolicy, error) {
	rows, err := s.DB.Query(ctx, `SELECT policy_class,active_days,pending_days,effective_at,
		updated_by::text,last_applied_at,last_error,updated_at
		FROM retention_policies
		WHERE pending_days IS NOT NULL AND effective_at<=now()
		ORDER BY policy_class`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []RetentionPolicy
	for rows.Next() {
		var item RetentionPolicy
		if err := rows.Scan(&item.PolicyClass, &item.ActiveDays, &item.PendingDays,
			&item.EffectiveAt, &item.UpdatedBy, &item.LastAppliedAt, &item.LastError,
			&item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CompleteRetentionPolicy(
	ctx context.Context, class string, days int, expectedUpdatedAt time.Time,
) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE retention_policies SET active_days=$2,pending_days=NULL,
		effective_at=NULL,last_applied_at=now(),last_error=NULL,updated_at=now()
		WHERE policy_class=$1 AND pending_days=$2 AND updated_at=$3`,
		class, days, expectedUpdatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("retention policy changed while it was being applied")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(action,resource_type,resource_id,details)
		VALUES('retention_applied','retention_policy',$1,$2)`,
		class, map[string]any{"days": days}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FailRetentionPolicy(
	ctx context.Context, class string, expectedUpdatedAt time.Time, applyErr error,
) error {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE retention_policies SET last_error=$3,updated_at=now()
		WHERE policy_class=$1 AND updated_at=$2`, class, expectedUpdatedAt, applyErr.Error())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_log
		(action,resource_type,resource_id,details)
		VALUES('retention_apply_failed','retention_policy',$1,$2)`,
		class, map[string]any{"error": applyErr.Error()}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
