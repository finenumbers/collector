package ingest

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"collector/internal/analytics"
	"collector/internal/archive"
	"collector/internal/equipment"
	"collector/internal/store"

	"github.com/google/uuid"
)

func TestSatelArchiveReplayWithMinIO(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	endpoint := os.Getenv("MINIO_TEST_ENDPOINT")
	if databaseURL == "" || endpoint == "" {
		t.Skip("POSTGRES_TEST_URL and MINIO_TEST_ENDPOINT are required")
	}
	ctx := context.Background()
	control, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	rawArchive, err := archive.Open(
		ctx, endpoint, os.Getenv("MINIO_TEST_ACCESS_KEY"),
		os.Getenv("MINIO_TEST_SECRET_KEY"), "collector-replay-test", false,
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := store.User{
		ID: uuid.New(), Username: "minio-replay-" + uuid.NewString(), Role: "admin",
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor.ID)
	})
	device, err := control.CreateDevice(ctx, store.NewDevice{
		Name:           "minio-replay-" + uuid.NewString(),
		SourceCategory: equipment.CategorySoftswitch,
		TemplateKey:    equipment.TemplateSatelRTUCDRV1,
		Timezone:       "Europe/Moscow",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = control.DeleteDevice(context.Background(), device.ID, actor, "127.0.0.1")
	})
	fixture, err := os.ReadFile("testdata/satel_rtu_cdr.csv")
	if err != nil {
		t.Fatal(err)
	}
	prefix := "cdr/" + device.ID.String() + "/"
	objectKey := prefix + "synthetic.csv"
	if err := rawArchive.Put(
		ctx, objectKey, bytes.NewReader(fixture), int64(len(fixture)), "text/csv",
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawArchive.DeletePrefix(context.Background(), prefix) })
	claim, err := control.ClaimIngestFile(
		ctx, device.ID, "synthetic.csv", objectKey, strings.Repeat("d", 64), int64(len(fixture)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.CompleteIngestFileWithParser(
		ctx, claim.ID, "archived", 0, 0, "",
		equipment.TemplateSatelRTUCDRV1, equipment.SatelRTUParserVersion,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := control.DB.Exec(ctx, `UPDATE ingest_files SET replay_state='pending',
		replay_template=$2,replay_version=$3,replay_requested_at=now()
		WHERE id=$1`, claim.ID, equipment.TemplateSatelRTUCDRV1,
		equipment.SatelRTUParserVersion); err != nil {
		t.Fatal(err)
	}
	warehouse := &countingCDRAnalytics{}
	watcher := &CDRWatcher{Store: control, Analytics: warehouse, Archive: rawArchive}
	if err := watcher.drainIngestReplays(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if warehouse.satelCalls != 1 || warehouse.satelRows != 4 {
		t.Fatalf("MinIO replay inserted batches=%d rows=%d", warehouse.satelCalls, warehouse.satelRows)
	}
	ledger, err := control.IngestFile(ctx, device.ID, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.ReplayState != "complete" || ledger.Status != "processed" ||
		ledger.ParserVersion != analytics.SatelRTUParserVersion {
		t.Fatalf("MinIO replay ledger = %#v", ledger)
	}
}
