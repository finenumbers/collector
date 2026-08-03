package workload

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAdmissionCancellationDoesNotLeakCapacity(t *testing.T) {
	manager := New(Options{Capacity: 1})
	_, release, err := manager.Acquire(context.Background(), Interactive)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err = manager.Acquire(ctx, Diagnostics); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire() error = %v", err)
	}
	release()
	acquired, nextRelease, err := manager.Acquire(context.Background(), Diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	nextRelease()
	if acquired == nil {
		t.Fatal("missing admitted context")
	}
	stats := manager.Snapshot()[Diagnostics]
	if stats.Active != 0 || stats.Waiting != 0 || stats.Rejected != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestInteractivePriorityAndHeavyLane(t *testing.T) {
	manager := New(Options{Capacity: 4})
	_, blockerRelease, err := manager.Acquire(context.Background(), Export)
	if err != nil {
		t.Fatal(err)
	}
	order := make(chan Class, 2)
	var releases sync.WaitGroup
	releases.Add(2)
	start := func(class Class) {
		go func() {
			_, release, acquireErr := manager.Acquire(context.Background(), class)
			if acquireErr != nil {
				t.Error(acquireErr)
				return
			}
			order <- class
			release()
			releases.Done()
		}()
	}
	start(CustomReplay)
	start(Interactive)
	deadline := time.Now().Add(time.Second)
	for manager.Snapshot()[Interactive].Waiting == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	blockerRelease()
	if first := <-order; first != Interactive {
		t.Fatalf("first admitted = %q, want interactive", first)
	}
	if second := <-order; second != CustomReplay {
		t.Fatalf("second admitted = %q, want custom replay", second)
	}
	releases.Wait()
}

func TestCustomReplayPreferredOverExportHeavyLane(t *testing.T) {
	manager := New(Options{Capacity: 4})
	// Hold 1 unit so neither heavy class (weight 4) can start until release.
	_, blockerRelease, err := manager.Acquire(context.Background(), Ingest)
	if err != nil {
		t.Fatal(err)
	}
	order := make(chan Class, 2)
	var releases sync.WaitGroup
	releases.Add(2)
	start := func(class Class) {
		go func() {
			_, release, acquireErr := manager.Acquire(context.Background(), class)
			if acquireErr != nil {
				t.Error(acquireErr)
				return
			}
			order <- class
			release()
			releases.Done()
		}()
	}
	start(Export)
	start(CustomReplay)
	deadline := time.Now().Add(time.Second)
	for (manager.Snapshot()[Export].Waiting == 0 || manager.Snapshot()[CustomReplay].Waiting == 0) &&
		time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	blockerRelease()
	if first := <-order; first != CustomReplay {
		t.Fatalf("first heavy admitted = %q, want custom_replay before export", first)
	}
	if second := <-order; second != Export {
		t.Fatalf("second heavy admitted = %q, want export", second)
	}
	releases.Wait()
}

func TestNestedAdmissionDoesNotDeadlock(t *testing.T) {
	manager := New(Options{Capacity: 1})
	ctx, release, err := manager.Acquire(context.Background(), Interactive)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_, nestedRelease, err := manager.Acquire(ctx, Export)
	if err != nil {
		t.Fatal(err)
	}
	nestedRelease()
}

func TestAdmissionRejectsBoundedQueue(t *testing.T) {
	manager := New(Options{Capacity: 1, MaxWaiting: 1})
	_, release, err := manager.Acquire(context.Background(), Interactive)
	if err != nil {
		t.Fatal(err)
	}
	waitingCtx, cancelWaiting := context.WithCancel(context.Background())
	waitingDone := make(chan error, 1)
	go func() {
		_, _, acquireErr := manager.Acquire(waitingCtx, Diagnostics)
		waitingDone <- acquireErr
	}()
	deadline := time.Now().Add(time.Second)
	for manager.Snapshot()[Diagnostics].Waiting == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if _, _, err = manager.Acquire(context.Background(), Ingest); !errors.Is(err, ErrRejected) {
		t.Fatalf("Acquire() error = %v, want ErrRejected", err)
	}
	cancelWaiting()
	<-waitingDone
	release()
}
