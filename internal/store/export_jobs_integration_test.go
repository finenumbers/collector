package store

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"collector/internal/equipment"

	"github.com/google/uuid"
)

func TestExportJobClaimAndLeaseRecovery(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err = control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	resetStoreIntegrationData(t, ctx, control)
	actor, err := control.CreateInitialAdmin(ctx, "export-claim-admin", "test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "export-claim-device", TemplateKey: equipment.TemplateEltex3410,
		Timezone: "UTC", SyslogSourceIP: "192.0.2.10",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	create := func() ExportJob {
		job, createErr := control.CreateExportJob(ctx, NewExportJob{
			DeviceID: device.ID, Dataset: "syslog",
			Format: "csv_zip", Timezone: "UTC", ActiveRevision: 1,
		}, actor, "127.0.0.1")
		if createErr != nil {
			t.Fatal(createErr)
		}
		return job
	}

	first := create()
	claimed, err := control.ClaimExportJob(ctx, "worker-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != first.ID || claimed.Status != "running" ||
		claimed.WorkerID != "worker-a" || claimed.StartedAt == nil ||
		claimed.HeartbeatAt == nil {
		t.Fatalf("claimed job = %#v", claimed)
	}

	if _, err = control.DB.Exec(ctx, `UPDATE export_jobs
		SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := control.ClaimExportJob(ctx, "worker-b", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if reclaimed.ID != first.ID || reclaimed.WorkerID != "worker-b" {
		t.Fatalf("reclaimed job = %#v", reclaimed)
	}
	if err = control.FinishExportJob(ctx, first.ID, "worker-b", "cancelled", "test cleanup"); err != nil {
		t.Fatal(err)
	}

	expected := map[uuid.UUID]struct{}{create().ID: {}, create().ID: {}}
	var wait sync.WaitGroup
	wait.Add(2)
	results := make(chan ExportJob, 2)
	failures := make(chan error, 2)
	for _, workerID := range []string{"worker-c", "worker-d"} {
		go func(id string) {
			defer wait.Done()
			job, claimErr := control.ClaimExportJob(ctx, id, time.Minute)
			if claimErr != nil {
				failures <- claimErr
				return
			}
			results <- job
		}(workerID)
	}
	wait.Wait()
	close(results)
	close(failures)
	for claimErr := range failures {
		t.Fatal(claimErr)
	}
	seen := make(map[uuid.UUID]struct{})
	for job := range results {
		if _, ok := expected[job.ID]; !ok {
			t.Fatalf("unexpected concurrent claim: %#v", job)
		}
		seen[job.ID] = struct{}{}
		if err = control.FinishExportJob(
			ctx, job.ID, job.WorkerID, "cancelled", "test cleanup",
		); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("concurrent workers claimed %d distinct jobs", len(seen))
	}
	if _, err = control.ClaimExportJob(ctx, "worker-e", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty queue error = %v, want ErrNotFound", err)
	}

	unavailable := create()
	changed, err := control.FailQueuedExportJob(
		ctx, device.ID, unavailable.ID, "export worker is unavailable; retry the export",
	)
	if err != nil || !changed {
		t.Fatalf("fail queued job: changed=%v err=%v", changed, err)
	}
	unavailable, err = control.ExportJob(ctx, device.ID, unavailable.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Status != "failed" || unavailable.FinishedAt == nil ||
		unavailable.Error != "export worker is unavailable; retry the export" {
		t.Fatalf("failed queued job = %#v", unavailable)
	}
}

func TestExportWorkerAvailableFromJobHeartbeats(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	control, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err = control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	resetStoreIntegrationData(t, ctx, control)
	actor, err := control.CreateInitialAdmin(ctx, "export-liveness-admin", "test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "export-liveness-device", TemplateKey: equipment.TemplateEltex3410,
		Timezone: "UTC", SyslogSourceIP: "192.0.2.11",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := control.ExportWorkerAvailable(ctx, ExportHeartbeatTimeout)
	if err != nil || !ok {
		t.Fatalf("idle queue available=%v err=%v", ok, err)
	}
	job, err := control.CreateExportJob(ctx, NewExportJob{
		DeviceID: device.ID, Dataset: "syslog",
		Format: "csv_zip", Timezone: "UTC", ActiveRevision: 1,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.DB.Exec(ctx, `UPDATE export_jobs
		SET created_at=now()-interval '5 minutes' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	ok, err = control.ExportWorkerAvailable(ctx, time.Minute)
	if err != nil || ok {
		t.Fatalf("stale queued job available=%v err=%v", ok, err)
	}
	claimed, err := control.ClaimExportJob(ctx, "liveness-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ok, err = control.ExportWorkerAvailable(ctx, ExportHeartbeatTimeout)
	if err != nil || !ok {
		t.Fatalf("fresh running job available=%v err=%v", ok, err)
	}
	if _, err = control.DB.Exec(ctx, `UPDATE export_jobs
		SET heartbeat_at=now()-interval '5 minutes',
			started_at=now()-interval '5 minutes' WHERE id=$1`, claimed.ID); err != nil {
		t.Fatal(err)
	}
	ok, err = control.ExportWorkerAvailable(ctx, time.Minute)
	if err != nil || ok {
		t.Fatalf("stale running job available=%v err=%v", ok, err)
	}
	_ = control.FinishExportJob(ctx, claimed.ID, "liveness-worker", "cancelled", "cleanup")
}

func TestClickHouseHeavyLaneSerializesAndCancels(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	control, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	release, err := control.AcquireClickHouseHeavyLane(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancelWait()
	if _, err = control.AcquireClickHouseHeavyLane(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("competing lane error = %v", err)
	}
	release()
	nextRelease, err := control.AcquireClickHouseHeavyLane(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nextRelease()
}
