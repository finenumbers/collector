package httpapi

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiagnosticsLeaderCancellationDoesNotCancelSharedRefresh(t *testing.T) {
	var loads atomic.Int32
	started := make(chan struct{})
	unblock := make(chan struct{})
	server := &Server{diagnosticsLoad: func(ctx context.Context) (map[string]any, error) {
		loads.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-unblock:
			return map[string]any{"ok": true}, nil
		}
	}}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := server.cachedDiagnostics(leaderCtx)
		leaderDone <- err
	}()
	<-started
	followerDone := make(chan error, 1)
	go func() {
		_, err := server.cachedDiagnostics(context.Background())
		followerDone <- err
	}()
	cancelLeader()
	if err := <-leaderDone; err == nil {
		t.Fatal("leader should observe cancellation")
	}
	close(unblock)
	select {
	case err := <-followerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("follower did not receive coalesced refresh")
	}
	if loads.Load() != 1 {
		t.Fatalf("refresh count = %d, want 1", loads.Load())
	}
}
