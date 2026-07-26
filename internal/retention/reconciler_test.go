package retention

import (
	"context"
	"errors"
	"testing"
	"time"

	"collector/internal/store"
)

type fakePolicyStore struct {
	policies  []store.RetentionPolicy
	completed bool
	failed    error
	released  bool
	lockAfter int
	lockCalls int
}

func (s *fakePolicyStore) TryRetentionLock(context.Context) (func(), bool, error) {
	s.lockCalls++
	if s.lockCalls <= s.lockAfter {
		return nil, false, nil
	}
	return func() { s.released = true }, true, nil
}

func (s *fakePolicyStore) CleanupExpiredSessions(context.Context) error {
	return nil
}

func (s *fakePolicyStore) DueRetentionPolicies(context.Context) ([]store.RetentionPolicy, error) {
	return s.policies, nil
}

func (s *fakePolicyStore) CompleteRetentionPolicy(
	context.Context, string, int, time.Time,
) error {
	s.completed = true
	return nil
}

func (s *fakePolicyStore) FailRetentionPolicy(
	_ context.Context, _ string, _ time.Time, applyErr error,
) error {
	s.failed = applyErr
	return nil
}

type fakeAnalyticsRetention struct {
	err error
}

func (a fakeAnalyticsRetention) ApplyRetention(context.Context, string, int) error {
	return a.err
}

func TestReconcilerCompletesImmediatelyDuePolicy(t *testing.T) {
	days := 30
	control := &fakePolicyStore{policies: []store.RetentionPolicy{{
		PolicyClass: "syslog", PendingDays: &days, UpdatedAt: time.Now(),
	}}}
	reconciler := &Reconciler{
		Store: control, Analytics: fakeAnalyticsRetention{},
	}
	if err := reconciler.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !control.completed || control.failed != nil || !control.released {
		t.Fatalf("unexpected reconciliation state: %+v", control)
	}
}

func TestReconcilerRecordsBackendFailureForRetry(t *testing.T) {
	days := 14
	applyErr := errors.New("clickhouse unavailable")
	control := &fakePolicyStore{policies: []store.RetentionPolicy{{
		PolicyClass: "cdr", PendingDays: &days, UpdatedAt: time.Now(),
	}}}
	reconciler := &Reconciler{
		Store: control, Analytics: fakeAnalyticsRetention{err: applyErr},
	}
	if err := reconciler.Run(context.Background()); !errors.Is(err, applyErr) {
		t.Fatalf("got %v, want backend error", err)
	}
	if control.completed || !errors.Is(control.failed, applyErr) || !control.released {
		t.Fatalf("unexpected reconciliation state: %+v", control)
	}
}

func TestRunNowWaitsForConcurrentReconciliation(t *testing.T) {
	days := 45
	control := &fakePolicyStore{
		lockAfter: 1,
		policies: []store.RetentionPolicy{{
			PolicyClass: "syslog", PendingDays: &days, UpdatedAt: time.Now(),
		}},
	}
	reconciler := &Reconciler{
		Store: control, Analytics: fakeAnalyticsRetention{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := reconciler.RunNow(ctx); err != nil {
		t.Fatal(err)
	}
	if control.lockCalls != 2 || !control.completed {
		t.Fatalf("lockCalls=%d completed=%v", control.lockCalls, control.completed)
	}
}

func TestBackgroundRunSkipsHeldLock(t *testing.T) {
	control := &fakePolicyStore{lockAfter: 1}
	reconciler := &Reconciler{
		Store: control, Analytics: fakeAnalyticsRetention{},
	}
	if err := reconciler.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if control.lockCalls != 1 || control.completed {
		t.Fatalf("lockCalls=%d completed=%v", control.lockCalls, control.completed)
	}
}
