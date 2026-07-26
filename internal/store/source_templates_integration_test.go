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

	raw, err := control.CreateDevice(ctx, NewDevice{
		Name: "raw-" + uuid.NewString(), SourceCategory: equipment.CategorySoftswitch,
		TemplateKey: equipment.TemplateSoftswitchRawV1, Timezone: "UTC",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = control.DeleteDevice(context.Background(), raw.ID, actor, "127.0.0.1")
	})
	if raw.SyslogSourceIP != "" || raw.AntifraudEnabled ||
		!strings.HasPrefix(raw.FTPUsername, "ssw_") || raw.Capabilities.TypedCDR {
		t.Fatalf("invalid raw source: %#v", raw)
	}
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	raw, err = control.Device(ctx, raw.ID)
	if err != nil {
		t.Fatal(err)
	}
	if raw.TemplateKey != equipment.TemplateSoftswitchRawV1 || raw.Firmware != "raw" {
		t.Fatalf("migration replay changed raw source identity: %#v", raw)
	}
	raw, err = control.UpdateDevice(ctx, raw.ID, DeviceUpdate{
		Name: raw.Name, SourceCategory: equipment.CategorySoftswitch,
		TemplateKey: equipment.TemplateSoftswitchRawV1,
		Timezone:    "Europe/Moscow", Enabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if raw.ActiveTimezone != "Europe/Moscow" ||
		raw.ActiveTimezoneRevision != raw.TimezoneRevision {
		t.Fatalf("raw timezone was not activated immediately: %#v", raw)
	}
	items, err := control.ListDevicesByCategory(ctx, equipment.CategorySoftswitch)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range items {
		found = found || item.ID == raw.ID
	}
	if !found {
		t.Fatal("raw source missing from category filter")
	}
	replayFile, err := control.ClaimIngestFile(
		ctx, raw.ID, "synthetic.csv", "cdr/synthetic", strings.Repeat("a", 64), 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.CompleteIngestFileWithParser(
		ctx, replayFile.ID, "archived", 0, 0, "",
		equipment.TemplateSoftswitchRawV1, "raw-archive-v1",
	); err != nil {
		t.Fatal(err)
	}
	raw, err = control.UpdateDevice(ctx, raw.ID, DeviceUpdate{
		Name: raw.Name, SourceCategory: equipment.CategorySoftswitch,
		TemplateKey: equipment.TemplateSatelRTUCDRV1,
		Timezone:    "Europe/Moscow", Enabled: true,
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if raw.ActiveTimezone != "Europe/Moscow" ||
		raw.ActiveTimezoneRevision != raw.TimezoneRevision {
		t.Fatalf("Satel timezone was not activated atomically: %#v", raw)
	}
	queued, err := control.IngestFile(ctx, raw.ID, replayFile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if queued.ReplayState != "pending" ||
		queued.ReplayTemplate != equipment.TemplateSatelRTUCDRV1 ||
		queued.ReplayVersion != equipment.SatelRTUParserVersion ||
		queued.ParserTemplate != equipment.TemplateSoftswitchRawV1 ||
		queued.ObjectKey != "cdr/synthetic" {
		t.Fatalf("raw-to-Satel update did not atomically enqueue archive: %#v", queued)
	}
	firstClaim, err := control.ClaimNextIngestReplay(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if firstClaim.ID != replayFile.ID || firstClaim.Attempts != 1 {
		t.Fatalf("unexpected replay claim: %#v", firstClaim)
	}
	if _, err := control.DB.Exec(ctx, `UPDATE ingest_files
		SET replay_started_at=now()-interval '10 minutes' WHERE id=$1`, firstClaim.ID); err != nil {
		t.Fatal(err)
	}
	secondClaim, err := control.ClaimNextIngestReplay(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if secondClaim.ID != replayFile.ID || secondClaim.Attempts != 2 {
		t.Fatalf("replay restart was not durable: %#v", secondClaim)
	}
	if err := control.CompleteIngestReplay(
		ctx, secondClaim.ID, "processed", 4, 4, "",
		equipment.TemplateSatelRTUCDRV1, equipment.SatelRTUParserVersion,
	); err != nil {
		t.Fatal(err)
	}
	completed, err := control.IngestFile(ctx, raw.ID, replayFile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.ReplayState != "complete" || completed.ParserVersion !=
		equipment.SatelRTUParserVersion || completed.RowsValid != 4 ||
		completed.ReplayCompleted == nil {
		t.Fatalf("replay completion state is incomplete: %#v", completed)
	}

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
		satel.ActiveTimezoneRevision != satel.TimezoneRevision {
		t.Fatalf("invalid Satel source: %#v", satel)
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
