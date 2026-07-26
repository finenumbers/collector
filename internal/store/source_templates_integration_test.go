package store

import (
	"context"
	"os"
	"strings"
	"testing"

	"collector/internal/equipment"

	"github.com/google/uuid"
)

func TestSourceTemplateMigrationAndCompatibility(t *testing.T) {
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
	for range 2 {
		if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
			t.Fatal(err)
		}
	}
	resetStoreIntegrationData(t, ctx, control)

	actor := User{ID: uuid.New(), Username: "templates-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor.ID)
	})

	satel, err := control.CreateDevice(ctx, NewDevice{
		Name: "satel-" + uuid.NewString(), SourceCategory: equipment.CategorySoftswitch,
		TemplateKey: equipment.TemplateSatelRTUCDRV1, Timezone: "Asia/Tokyo",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = control.DeleteDevice(context.Background(), satel.ID, actor, "127.0.0.1")
	})
	if !satel.Capabilities.TypedCDR || !satel.Capabilities.RawCDR ||
		satel.Capabilities.Syslog || satel.Firmware != equipment.TemplateSatelRTUCDRV1 ||
		satel.ActiveTimezone != "Asia/Tokyo" ||
		satel.ActiveTimezoneRevision != satel.TimezoneRevision ||
		!strings.HasPrefix(satel.FTPUsername, "ssw_") {
		t.Fatalf("invalid Satel source: %#v", satel)
	}
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	satel, err = control.Device(ctx, satel.ID)
	if err != nil {
		t.Fatal(err)
	}
	if satel.TemplateKey != equipment.TemplateSatelRTUCDRV1 ||
		satel.Firmware != equipment.TemplateSatelRTUCDRV1 {
		t.Fatalf("migration replay changed Satel source identity: %#v", satel)
	}
	satel, err = control.UpdateDevice(ctx, satel.ID, DeviceUpdate{
		Name: satel.Name, SourceCategory: equipment.CategorySoftswitch,
		TemplateKey: equipment.TemplateSatelRTUCDRV1,
		Timezone:    "Europe/Moscow", Enabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if satel.ActiveTimezone != "Europe/Moscow" ||
		satel.ActiveTimezoneRevision != satel.TimezoneRevision {
		t.Fatalf("Satel timezone was not activated immediately: %#v", satel)
	}
	items, err := control.ListDevicesByCategory(ctx, equipment.CategorySoftswitch)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		found = found || item.ID == satel.ID
	}
	if !found {
		t.Fatal("Satel source missing from category filter")
	}

	sourceIP := "2001:db8::" + strings.ReplaceAll(uuid.NewString()[:4], "-", "")
	eltex, err := control.CreateDevice(ctx, NewDevice{
		Name: "eltex-" + uuid.NewString(), Firmware: FirmwareScheme3410,
		Timezone: "UTC", SyslogSourceIP: sourceIP,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = control.DeleteDevice(context.Background(), eltex.ID, actor, "127.0.0.1")
	})
	if eltex.TemplateKey != equipment.TemplateEltex3410 ||
		eltex.SourceCategory != equipment.CategoryEquipment {
		t.Fatalf("legacy request inferred wrong template: %#v", eltex)
	}
}

func TestRawSoftswitchRemovalMigrationConvertsLegacySource(t *testing.T) {
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
	resetStoreIntegrationData(t, ctx, control)

	actor := User{ID: uuid.New(), Username: "raw-removal-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, NewDevice{
		Name: "legacy-raw-" + uuid.NewString(), SourceCategory: equipment.CategorySoftswitch,
		TemplateKey: equipment.TemplateSatelRTUCDRV1, Timezone: "UTC",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `UPDATE devices SET
		template_key='softswitch-cdr-raw-v1',firmware='raw' WHERE id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	file, err := control.ClaimIngestFile(
		ctx, device.ID, "legacy.csv", "cdr/legacy.csv", strings.Repeat("f", 64), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.CompleteIngestFileWithParser(
		ctx, file.ID, "archived", 0, 0, "",
		"softswitch-cdr-raw-v1", "raw-archive-v1",
	); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../migrations/postgres/014_remove_raw_softswitch_template.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}
	converted, err := control.Device(ctx, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	queued, err := control.IngestFile(ctx, device.ID, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	if converted.TemplateKey != equipment.TemplateSatelRTUCDRV1 ||
		converted.Firmware != equipment.TemplateSatelRTUCDRV1 ||
		queued.ReplayState != "pending" ||
		queued.ReplayTemplate != equipment.TemplateSatelRTUCDRV1 {
		t.Fatalf("legacy raw source was not converted: device=%#v file=%#v", converted, queued)
	}
}
