package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"collector/internal/equipment"

	"github.com/google/uuid"
)

func TestSyslogArchiveClaimRetryAndEnsure(t *testing.T) {
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
	if _, err := control.DB.Exec(ctx, `UPDATE syslog_archive_worker SET
		worker_id='', heartbeat_at=NULL, last_tick_at=NULL, last_error=''`); err != nil {
		t.Fatal(err)
	}

	state, err := control.SyslogArchiveWorkerState(ctx, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if state.Alive {
		t.Fatal("null heartbeat must not look alive")
	}
	if err := control.TouchSyslogArchiveWorker(ctx, "worker-a"); err != nil {
		t.Fatal(err)
	}
	state, err = control.SyslogArchiveWorkerState(ctx, time.Minute)
	if err != nil || !state.Alive || state.WorkerID != "worker-a" {
		t.Fatalf("fresh heartbeat: %#v err=%v", state, err)
	}

	actor, err := control.CreateInitialAdmin(ctx, "archive-claim-admin", "test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "archive-claim-device", TemplateKey: equipment.TemplateEltex3410,
		Timezone: "UTC", SyslogSourceIP: "192.0.2.88", DeviceSign: "fixer",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	failedBuild := uuid.New()
	hour := time.Date(2026, 8, 17, 14, 10, 0, 0, time.UTC)
	if _, err := control.DB.Exec(ctx, `
		INSERT INTO syslog_archive_jobs
			(id,device_id,hour_start,archive_name,remote_dir,timezone,status,local_path,next_attempt_at)
		VALUES ($1,$2,$3,'fixer_17.08.2026_14-10.zip','/old','UTC','failed','',now())`,
		failedBuild, device.ID, hour); err != nil {
		t.Fatal(err)
	}
	claimed, err := control.ClaimSyslogArchiveJob(ctx, "worker-a", time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != failedBuild || claimed.Status != SyslogArchiveStatusBuilding {
		t.Fatalf("failed without path should rebuild, got %#v", claimed)
	}

	failedUpload := uuid.New()
	hour2 := hour.Add(10 * time.Minute)
	if _, err := control.DB.Exec(ctx, `
		INSERT INTO syslog_archive_jobs
			(id,device_id,hour_start,archive_name,remote_dir,timezone,status,local_path,next_attempt_at)
		VALUES ($1,$2,$3,'fixer_17.08.2026_14-20.zip','/old','UTC','failed','/tmp/ready.zip',now())`,
		failedUpload, device.ID, hour2); err != nil {
		t.Fatal(err)
	}
	claimed, err = control.ClaimSyslogArchiveJob(ctx, "worker-a", time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.ID != failedUpload || claimed.Status != SyslogArchiveStatusUploading {
		t.Fatalf("failed with path should upload, got %#v", claimed)
	}

	failedEmpty := uuid.New()
	hour3 := hour.Add(20 * time.Minute)
	if _, err := control.DB.Exec(ctx, `
		INSERT INTO syslog_archive_jobs
			(id,device_id,hour_start,archive_name,remote_dir,timezone,status,local_path,next_attempt_at)
		VALUES ($1,$2,$3,'fixer_17.08.2026_14-30.zip','/old','UTC','failed','',now())`,
		failedEmpty, device.ID, hour3); err != nil {
		t.Fatal(err)
	}
	if _, err := control.ClaimSyslogArchiveJob(ctx, "worker-a", time.Minute, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed without path must not claim when allowBuild=false, err=%v", err)
	}

	pendingHour := hour.Add(30 * time.Minute)
	first, err := control.EnsureSyslogArchiveJob(ctx, device.ID, pendingHour, "fixer_17.08.2026_14-40.zip", "/old", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := control.EnsureSyslogArchiveJob(ctx, device.ID, pendingHour, "fixer_17.08.2026_14-40.zip", "/SMG/Fixer/Syslog", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != first.ID || updated.RemoteDir != "/SMG/Fixer/Syslog" {
		t.Fatalf("pending job remote dir not updated: %#v", updated)
	}

	uploadedHour := hour.Add(40 * time.Minute)
	uploadedID := uuid.New()
	if _, err := control.DB.Exec(ctx, `
		INSERT INTO syslog_archive_jobs
			(id,device_id,hour_start,archive_name,remote_dir,timezone,status)
		VALUES ($1,$2,$3,'fixer_17.08.2026_14.zip','/old','UTC','uploaded')`,
		uploadedID, device.ID, uploadedHour); err != nil {
		t.Fatal(err)
	}
	kept, err := control.EnsureSyslogArchiveJob(ctx, device.ID, uploadedHour, "fixer_17.08.2026_14-50.zip", "/new", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if kept.RemoteDir != "/old" || kept.ArchiveName != "fixer_17.08.2026_14.zip" || kept.Status != SyslogArchiveStatusUploaded {
		t.Fatalf("uploaded leftover must not be rewritten: %#v", kept)
	}
}
