package store

import (
	"context"
	"testing"
	"time"

	"collector/internal/customprojection"

	"github.com/google/uuid"
)

func TestProjectionGenerationAndReconciliationLease(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "projection-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "projection-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::1234", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	bucket := time.Date(2026, 7, 27, 3, 0, 0, 0, time.UTC)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{bucket},
	); err != nil {
		t.Fatal(err)
	}
	first, ok, err := control.ClaimCustomProjectionJob(ctx, "worker-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("first claim: ok=%v err=%v", ok, err)
	}
	if _, ok, err := control.ClaimCustomProjectionJob(ctx, "worker-b", time.Minute); err != nil || ok {
		t.Fatalf("same-device concurrent projection claim: ok=%v err=%v", ok, err)
	}
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{bucket},
	); err != nil {
		t.Fatal(err)
	}
	if err := control.CompleteCustomProjectionJob(
		ctx, first, customprojection.Snapshot{},
	); err != nil {
		t.Fatal(err)
	}
	var status string
	var generation uint64
	if err := control.DB.QueryRow(ctx, `SELECT status,generation
		FROM custom_projection_jobs WHERE id=$1`, first.ID).Scan(&status, &generation); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || generation <= first.Generation {
		t.Fatalf("late generation was lost: status=%s generation=%d claimed=%d",
			status, generation, first.Generation)
	}

	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_reconciliation_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	if err := control.EnqueueCDRReconciliationBuckets(
		ctx, device.ID, 1, []time.Time{bucket, bucket.Add(time.Hour)},
	); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := control.ClaimReconciliationJob(ctx, "reconcile-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("reconciliation claim: ok=%v err=%v", ok, err)
	}
	if _, ok, err := control.ClaimReconciliationJob(ctx, "reconcile-b", time.Minute); err != nil || ok {
		t.Fatalf("same-device concurrent reconciliation claim: ok=%v err=%v", ok, err)
	}
	if err := control.CompleteReconciliationJob(ctx, claimed); err != nil {
		t.Fatal(err)
	}
	secondReconciliation, ok, err := control.ClaimReconciliationJob(
		ctx, "reconcile-b", time.Minute,
	)
	if err != nil || !ok {
		t.Fatalf("second bucket was not released after lease completion: ok=%v err=%v", ok, err)
	}
	agingDeadline := time.Now().UTC().Add(30 * time.Minute)
	if err := control.CommitReconciliation(
		ctx, secondReconciliation, &agingDeadline, func(context.Context) error { return nil },
	); err != nil {
		t.Fatal(err)
	}
	if err := control.DB.QueryRow(ctx, `SELECT status FROM custom_reconciliation_jobs
		WHERE id=$1`, secondReconciliation.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("aging deadline did not retain reconciliation job: %s", status)
	}

	cutoverJob, ok, err := control.ClaimCustomProjectionJob(ctx, "cutover-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("cutover claim: ok=%v err=%v", ok, err)
	}
	entered, releaseCutover := make(chan struct{}), make(chan struct{})
	cutoverDone := make(chan error, 1)
	go func() {
		cutoverDone <- control.CutoverCustomProjection(
			context.Background(), cutoverJob, customprojection.Snapshot{
				ID: uuid.New(), DeviceID: device.ID, PolicyRevision: 1,
				ProjectionSeq: cutoverJob.ProjectionSeq,
			},
			func(context.Context) error {
				close(entered)
				<-releaseCutover
				return nil
			},
		)
	}()
	<-entered
	toggleDone := make(chan error, 1)
	go func() {
		_, updateErr := control.UpdateDevice(context.Background(), device.ID, DeviceUpdate{
			Name: device.Name, SourceCategory: device.SourceCategory,
			TemplateKey: device.TemplateKey, Firmware: device.Firmware,
			Timezone: device.Timezone, SyslogSourceIP: device.SyslogSourceIP,
			DeviceSign: device.DeviceSign, AntifraudEnabled: false, Enabled: true,
		}, actor, "127.0.0.1")
		toggleDone <- updateErr
	}()
	select {
	case err := <-toggleDone:
		t.Fatalf("toggle bypassed deployment-wide cutover lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseCutover)
	if err := <-cutoverDone; err != nil {
		t.Fatal(err)
	}
	if err := <-toggleDone; err != nil {
		t.Fatal(err)
	}
}
