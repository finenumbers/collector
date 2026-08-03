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

}

func TestCustomProjectionClaimPrefersOpenHourThenBacklog(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "claim-order-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "claim-order-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::2345", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	openHour := time.Now().UTC().Truncate(time.Hour)
	backlog := openHour.Add(-2 * time.Hour)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{backlog, openHour},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO custom_projection_jobs
		(device_id,kind,status,policy_revision,next_attempt_at)
		VALUES ($1,'discover','pending',1,now())`, device.ID); err != nil {
		t.Fatal(err)
	}
	first, ok, err := control.ClaimCustomProjectionJob(ctx, "order-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("open-hour claim: ok=%v err=%v", ok, err)
	}
	if first.Kind != customprojection.JobBucket || !first.BucketStart.Equal(openHour) {
		t.Fatalf("first claim=%#v, want open-hour bucket", first)
	}
	if err := control.CompleteCustomProjectionJob(ctx, first, customprojection.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	// Completing may requeue the same generation as pending if arrivals bumped it;
	// force the open-hour row out of the way so backlog can surface next.
	if _, err := control.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET status='completed',lease_expires_at=NULL,worker_id=NULL
		WHERE device_id=$1 AND kind='bucket' AND bucket_start=$2`,
		device.ID, openHour); err != nil {
		t.Fatal(err)
	}
	second, ok, err := control.ClaimCustomProjectionJob(ctx, "order-b", time.Minute)
	if err != nil || !ok {
		t.Fatalf("backlog claim: ok=%v err=%v", ok, err)
	}
	if second.Kind != customprojection.JobBucket || !second.BucketStart.Equal(backlog) {
		t.Fatalf("second claim=%#v, want backlog bucket before discover", second)
	}
	if err := control.CompleteCustomProjectionJob(ctx, second, customprojection.Snapshot{}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET status='completed',lease_expires_at=NULL,worker_id=NULL
		WHERE id=$1`, second.ID); err != nil {
		t.Fatal(err)
	}
	third, ok, err := control.ClaimCustomProjectionJob(ctx, "order-c", time.Minute)
	if err != nil || !ok {
		t.Fatalf("discover claim: ok=%v err=%v", ok, err)
	}
	if third.Kind != customprojection.JobDiscover {
		t.Fatalf("third claim kind=%s, want discover after backlog", third.Kind)
	}
}

func TestFailCustomProjectionJobIsOwnershipSafe(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "fail-own-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "fail-own-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::3456", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	bucket := time.Date(2026, 7, 27, 5, 0, 0, 0, time.UTC)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{bucket},
	); err != nil {
		t.Fatal(err)
	}
	owner, ok, err := control.ClaimCustomProjectionJob(ctx, "owner", time.Minute)
	if err != nil || !ok {
		t.Fatalf("owner claim: ok=%v err=%v", ok, err)
	}
	stale := owner
	stale.WorkerID = "stale-worker"
	if err := control.FailCustomProjectionJob(ctx, stale, context.DeadlineExceeded, time.Second); err != nil {
		t.Fatal(err)
	}
	var status, workerID string
	if err := control.DB.QueryRow(ctx, `SELECT status,COALESCE(worker_id,'')
		FROM custom_projection_jobs WHERE id=$1`, owner.ID).Scan(&status, &workerID); err != nil {
		t.Fatal(err)
	}
	if status != "running" || workerID != "owner" {
		t.Fatalf("stale fail mutated job: status=%s worker=%s", status, workerID)
	}
	var leaseOwner string
	if err := control.DB.QueryRow(ctx, `SELECT worker_id FROM custom_projection_device_leases
		WHERE device_id=$1`, device.ID).Scan(&leaseOwner); err != nil {
		t.Fatal(err)
	}
	if leaseOwner != "owner" {
		t.Fatalf("stale fail released device lease to %q", leaseOwner)
	}
}

func TestClaimOpenHourWhileClosedHourLeased(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "open-lease-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "open-lease-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::7001", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	openHour := time.Now().UTC().Truncate(time.Hour)
	closed := openHour.Add(-3 * time.Hour)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{closed, openHour},
	); err != nil {
		t.Fatal(err)
	}
	// Closed hour holds the exclusive device lease; open hour stays pending.
	if _, err := control.DB.Exec(ctx, `UPDATE custom_projection_jobs
		SET status='running',worker_id='closed-owner',lease_expires_at=now()+interval '1 minute',
			claimed_generation=generation
		WHERE device_id=$1 AND kind='bucket' AND bucket_start=$2`,
		device.ID, closed); err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO custom_projection_device_leases
		(device_id,worker_id,lease_expires_at) VALUES ($1,'closed-owner',now()+interval '1 minute')
		ON CONFLICT (device_id) DO UPDATE SET
			worker_id=EXCLUDED.worker_id,lease_expires_at=EXCLUDED.lease_expires_at,updated_at=now()`,
		device.ID); err != nil {
		t.Fatal(err)
	}
	openJob, ok, err := control.ClaimCustomProjectionJob(ctx, "live-worker", time.Minute)
	if err != nil || !ok {
		t.Fatalf("open-hour claim beside closed lease: ok=%v err=%v", ok, err)
	}
	if !openJob.BucketStart.Equal(openHour) {
		t.Fatalf("claimed %#v, want open hour", openJob)
	}
	var openLeaseCount int
	if err := control.DB.QueryRow(ctx, `SELECT count(*) FROM custom_projection_device_leases
		WHERE device_id=$1 AND worker_id='live-worker'`, device.ID).Scan(&openLeaseCount); err != nil {
		t.Fatal(err)
	}
	if openLeaseCount != 0 {
		t.Fatalf("open-hour must not take device lease, count=%d", openLeaseCount)
	}
}

func TestClaimClosedHourWhileOpenHourRunningWithoutDeviceLease(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "closed-after-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "closed-after-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::7002", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	openHour := time.Now().UTC().Truncate(time.Hour)
	closed := openHour.Add(-2 * time.Hour)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{closed, openHour},
	); err != nil {
		t.Fatal(err)
	}
	openJob, ok, err := control.ClaimCustomProjectionJob(ctx, "live-a", time.Minute)
	if err != nil || !ok || !openJob.BucketStart.Equal(openHour) {
		t.Fatalf("open claim=%#v ok=%v err=%v", openJob, ok, err)
	}
	closedJob, ok, err := control.ClaimCustomProjectionJob(ctx, "catchup-b", time.Minute)
	if err != nil || !ok {
		t.Fatalf("closed claim beside open hour: ok=%v err=%v", ok, err)
	}
	if !closedJob.BucketStart.Equal(closed) {
		t.Fatalf("claimed %#v, want closed hour", closedJob)
	}
	var leaseOwner string
	if err := control.DB.QueryRow(ctx, `SELECT worker_id FROM custom_projection_device_leases
		WHERE device_id=$1`, device.ID).Scan(&leaseOwner); err != nil {
		t.Fatal(err)
	}
	if leaseOwner != "catchup-b" {
		t.Fatalf("device lease owner=%q, want catchup-b", leaseOwner)
	}
}

func TestClosedHoursStillSerializedByDeviceLease(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "serial-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "serial-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::7003", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	hourA := time.Now().UTC().Truncate(time.Hour).Add(-4 * time.Hour)
	hourB := hourA.Add(-time.Hour)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{hourA, hourB},
	); err != nil {
		t.Fatal(err)
	}
	first, ok, err := control.ClaimCustomProjectionJob(ctx, "serial-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("first closed claim: ok=%v err=%v", ok, err)
	}
	if _, ok, err := control.ClaimCustomProjectionJob(ctx, "serial-b", time.Minute); err != nil || ok {
		t.Fatalf("second closed claim should be blocked: ok=%v err=%v", ok, err)
	}
	_ = first
}

func TestRefreshLeaseOpenHourWithoutDeviceLease(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "refresh-open-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "refresh-open-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::7004", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	openHour := time.Now().UTC().Truncate(time.Hour)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{openHour},
	); err != nil {
		t.Fatal(err)
	}
	job, ok, err := control.ClaimCustomProjectionJob(ctx, "refresh-live", time.Minute)
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if err := control.RefreshCustomProjectionLease(ctx, job, time.Minute); err != nil {
		t.Fatalf("open-hour refresh without device lease: %v", err)
	}
}

func TestCustomProjectionClaimPrefersBucketOverFrozenTip(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "fair-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	quiet, err := control.CreateDevice(ctx, NewDevice{
		Name: "quiet-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::6001", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	busy, err := control.CreateDevice(ctx, NewDevice{
		Name: "busy-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::6002", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `DELETE FROM custom_projection_jobs
		WHERE device_id IN ($1,$2)`, quiet.ID, busy.ID); err != nil {
		t.Fatal(err)
	}
	openHour := time.Now().UTC().Truncate(time.Hour)
	// Quiet SMG: only eternal discover + ancient watermark tip.
	if _, err := control.DB.Exec(ctx, `INSERT INTO custom_projection_jobs
		(device_id,kind,status,policy_revision,next_attempt_at,created_at)
		VALUES ($1,'discover','pending',1,now(),now()-interval '56 hours')`, quiet.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO custom_projection_watermarks
		(device_id,policy_revision,projection_seq,state,watermark_received_at,updated_at)
		VALUES ($1,1,1,'active',now()-interval '2 hours',now())
		ON CONFLICT (device_id) DO UPDATE SET
			watermark_received_at=EXCLUDED.watermark_received_at,state='active',updated_at=now()`,
		quiet.ID); err != nil {
		t.Fatal(err)
	}
	// Busy SMG: live open-hour bucket with a fresher watermark tip.
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, busy.ID, 1, []time.Time{openHour},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO custom_projection_watermarks
		(device_id,policy_revision,projection_seq,state,watermark_received_at,updated_at)
		VALUES ($1,1,1,'active',now()-interval '30 seconds',now())
		ON CONFLICT (device_id) DO UPDATE SET
			watermark_received_at=EXCLUDED.watermark_received_at,state='active',updated_at=now()`,
		busy.ID); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := control.ClaimCustomProjectionJob(ctx, "fair-a", time.Minute)
	if err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if claimed.DeviceID != busy.ID || claimed.Kind != customprojection.JobBucket {
		t.Fatalf("claimed=%#v, want busy open-hour bucket over quiet discover tip", claimed)
	}
}

func TestCustomProjectionQueueOldestAgeIgnoresDiscover(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "oldest-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "oldest-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::6003", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `DELETE FROM custom_projection_jobs WHERE device_id=$1`,
		device.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO custom_projection_jobs
		(device_id,kind,status,policy_revision,next_attempt_at,created_at,bucket_start)
		VALUES
		($1,'discover','pending',1,now(),now()-interval '56 hours',NULL),
		($1,'bucket','pending',1,now(),now()-interval '10 minutes',
			date_trunc('hour', now()-interval '2 hours'))`,
		device.ID); err != nil {
		t.Fatal(err)
	}
	stats, err := control.CustomProjectionQueueStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.OldestAge < 9*time.Minute || stats.OldestAge > 15*time.Minute {
		t.Fatalf("oldestAge=%s, want ~10m bucket age", stats.OldestAge)
	}
	if stats.DiscoverAge < 55*time.Hour {
		t.Fatalf("discoverAge=%s, want ~56h", stats.DiscoverAge)
	}
}

func TestProjectionCutoverHoldsToggleLock(t *testing.T) {
	control := isolatedMigrationStore(t)
	ctx := context.Background()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := User{ID: uuid.New(), Username: "cutover-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "cutover-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: "2001:db8::4567", AntifraudEnabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx,
		`DELETE FROM custom_projection_jobs WHERE device_id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	bucket := time.Date(2026, 7, 27, 6, 0, 0, 0, time.UTC)
	if err := control.EnqueueCustomProjectionBuckets(
		ctx, device.ID, 1, []time.Time{bucket},
	); err != nil {
		t.Fatal(err)
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
