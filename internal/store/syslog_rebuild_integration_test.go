package store

import (
	"context"
	"os"
	"testing"
	"time"

	"collector/internal/equipment"

	"github.com/google/uuid"
)

func TestSyslogParserRebuildJobCheckpointLifecycle(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	control, err := Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}

	actor := User{ID: uuid.New(), Username: "syslog-rebuild-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "syslog-rebuild-" + uuid.NewString(), SourceCategory: equipment.CategoryEquipment,
		TemplateKey: equipment.TemplateEltex3410, Firmware: FirmwareScheme3410,
		SyslogSourceIP: "192.0.2.44", Timezone: "UTC",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor.ID)
	})

	parserVersion := "integration-parser-" + uuid.NewString()
	firstEvent, watermarkEvent := uuid.New(), uuid.New()
	if firstEvent.String() > watermarkEvent.String() {
		firstEvent, watermarkEvent = watermarkEvent, firstEvent
	}
	for range 2 {
		if err := control.EnsureSyslogParserRebuildJob(
			ctx, device.ID, parserVersion, 20, watermarkEvent, 2,
		); err != nil {
			t.Fatal(err)
		}
	}
	job, err := control.ClaimSyslogParserRebuildJob(ctx, parserVersion, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if job.Attempts != 1 || job.TotalEvents != 2 || job.Status != "running" {
		t.Fatalf("unexpected initial job: %#v", job)
	}
	if err := control.AdvanceSyslogParserRebuildJob(ctx, job, 10, firstEvent, 1); err != nil {
		t.Fatal(err)
	}
	job, err = control.ClaimSyslogParserRebuildJob(ctx, parserVersion, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if job.CursorReceivedUS != 10 || job.CursorEventID != firstEvent ||
		job.ProcessedEvents != 1 || job.ProcessedBatches != 1 || job.Attempts != 2 {
		t.Fatalf("checkpoint was not durable: %#v", job)
	}
	if err := control.AdvanceSyslogParserRebuildJob(
		ctx, job, 20, watermarkEvent, 1,
	); err != nil {
		t.Fatal(err)
	}
	job, err = control.ClaimSyslogParserRebuildJob(ctx, parserVersion, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if job.ProcessedEvents != 2 || job.ProcessedBatches != 2 || job.Attempts != 3 {
		t.Fatalf("final checkpoint was not durable: %#v", job)
	}
	if err := control.CompleteSyslogParserRebuildJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if _, err := control.ClaimSyslogParserRebuildJob(ctx, parserVersion, time.Minute); err != ErrNotFound {
		t.Fatalf("completed job was claimable: %v", err)
	}
	jobs, err := control.ListSyslogParserRebuildJobs(ctx, parserVersion)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Status != "completed" || jobs[0].ProcessedEvents != 2 ||
		jobs[0].HeartbeatAt == nil || jobs[0].CompletedAt == nil {
		t.Fatalf("unexpected observable job state: %#v", jobs)
	}
}
