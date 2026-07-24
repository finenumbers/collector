package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestDevicePurgeAndUserAdministrationPostgres(t *testing.T) {
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
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	admin, err := control.CreateInitialAdmin(ctx, "purge-admin", "test-password-123")
	if err != nil {
		t.Fatal(err)
	}
	managed, err := control.CreateUser(
		ctx, "operator", "test-password-456", "viewer", admin, "127.0.0.1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.UpdateUser(ctx, admin.ID, UserUpdate{
		Role: "viewer", Active: true,
	}, admin, "127.0.0.1"); err == nil {
		t.Fatal("last administrator was allowed to demote itself")
	}
	if _, err := control.UpdateUser(ctx, managed.ID, UserUpdate{
		Role: "admin", Active: true,
	}, admin, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "purge-smg", SyslogSourceIP: "192.0.2.10", Timezone: "Asia/Novosibirsk",
	}, admin, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	release := control.LockDevicePurge(device.ID)
	if _, err := control.BeginDevicePurge(ctx, device.ID); err != nil {
		release()
		t.Fatal(err)
	}
	if _, err := control.DeviceTimeConfig(ctx, device.ID); !errors.Is(err, ErrDeviceDeleting) {
		release()
		t.Fatalf("time config during purge returned %v", err)
	}
	if err := control.FinalizeDevicePurge(ctx, device.ID); err != nil {
		release()
		t.Fatal(err)
	}
	release()
	if _, err := control.Device(ctx, device.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("device remains after purge: %v", err)
	}
	var auditRows int
	if err := control.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log
		WHERE resource_type='device' AND resource_id=$1`, device.ID.String()).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if auditRows != 0 {
		t.Fatalf("%d device audit rows remain after purge", auditRows)
	}
}
