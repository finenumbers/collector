package ingest

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"collector/internal/analytics"
	"collector/internal/archive"
	"collector/internal/equipment"
	"collector/internal/store"

	"github.com/google/uuid"
)

type countingCDRAnalytics struct {
	calls      int
	satelCalls int
	satelRows  int
}

func (client *countingCDRAnalytics) InsertSatelRTUBatch(
	_ context.Context, records []analytics.SatelRTURecord,
) error {
	client.satelCalls++
	client.satelRows += len(records)
	return nil
}

type memoryCDRArchive struct {
	objects    map[string][]byte
	openSignal chan struct{}
	openOnce   sync.Once
}

func (memory *memoryCDRArchive) Put(
	_ context.Context, key string, reader io.Reader, _ int64, _ string,
) error {
	content, err := io.ReadAll(reader)
	if err == nil {
		memory.objects[key] = content
	}
	return err
}

func (memory *memoryCDRArchive) OpenObject(
	_ context.Context, key string,
) (archive.Object, error) {
	if memory.openSignal != nil {
		memory.openOnce.Do(func() { close(memory.openSignal) })
	}
	content, ok := memory.objects[key]
	if !ok {
		return archive.Object{}, os.ErrNotExist
	}
	return archive.Object{
		Reader: io.NopCloser(bytes.NewReader(content)), Size: int64(len(content)),
		ContentType: "text/csv",
	}, nil
}

func (client *countingCDRAnalytics) InsertCDRBatch(
	context.Context, []analytics.CDRRecord,
) error {
	client.calls++
	return nil
}

func TestTypedTemplateCallsAnalytics(t *testing.T) {
	template, err := equipment.Resolve(equipment.TemplateEltex3410)
	if err != nil {
		t.Fatal(err)
	}
	client := &countingCDRAnalytics{}
	if err := insertCDRForTemplate(context.Background(), template, client, nil); err != nil {
		t.Fatal(err)
	}
	if client.calls != 1 {
		t.Fatalf("typed CDR made %d analytics calls", client.calls)
	}
}

func TestSatelTemplateCallsDedicatedAnalytics(t *testing.T) {
	template, err := equipment.Resolve(equipment.TemplateSatelRTUCDRV1)
	if err != nil {
		t.Fatal(err)
	}
	client := &countingCDRAnalytics{}
	if err := insertSatelRTUForTemplate(context.Background(), template, client, nil); err != nil {
		t.Fatal(err)
	}
	if client.satelCalls != 1 || client.calls != 0 {
		t.Fatalf("Satel dispatch used generic=%d dedicated=%d", client.calls, client.satelCalls)
	}
}

func TestSatelArchiveReplayRestartAndPartialQuarantine(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
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
	actor := store.User{
		ID: uuid.New(), Username: "watcher-replay-" + uuid.NewString(), Role: "admin",
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor.ID)
	})
	device, err := control.CreateDevice(ctx, store.NewDevice{
		Name: "replay-" + uuid.NewString(), SourceCategory: equipment.CategorySoftswitch,
		TemplateKey: equipment.TemplateSatelRTUCDRV1, Timezone: "UTC",
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
	partial := []byte(strings.Replace(string(fixture), `"synthetic-487"`, `""`, 1))
	memoryArchive := &memoryCDRArchive{
		objects: map[string][]byte{
			"cdr/replay/valid": fixture, "cdr/replay/partial": partial,
		},
		openSignal: make(chan struct{}),
	}
	fileIDs := make([]uuid.UUID, 0, 2)
	for index, item := range []struct {
		key, checksum string
	}{
		{key: "cdr/replay/valid", checksum: strings.Repeat("b", 64)},
		{key: "cdr/replay/partial", checksum: strings.Repeat("c", 64)},
	} {
		claim, err := control.ClaimIngestFile(
			ctx, device.ID, "synthetic-"+string(rune('a'+index))+".csv",
			item.key, item.checksum, int64(len(memoryArchive.objects[item.key])),
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
		fileIDs = append(fileIDs, claim.ID)
	}
	progress, err := control.DeviceIngestReplayProgress(ctx, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if progress.Pending != 2 || progress.Processing != 0 || progress.Complete != 0 {
		t.Fatalf("unexpected initial replay progress: %#v", progress)
	}
	memoryArchive.openSignal = make(chan struct{})
	memoryArchive.openOnce = sync.Once{}
	warehouse := &countingCDRAnalytics{}
	watcher := &CDRWatcher{
		Store: control, Analytics: warehouse, Archive: memoryArchive,
	}
	unlockPurge := control.LockDevicePurge(device.ID)
	replayDone := make(chan error, 1)
	go func() {
		replayDone <- watcher.drainIngestReplays(ctx, 100)
	}()
	select {
	case <-memoryArchive.openSignal:
		unlockPurge()
		t.Fatal("replay opened archive without acquiring the device write lock")
	case <-time.After(100 * time.Millisecond):
	}
	unlockPurge()
	if err := <-replayDone; err != nil {
		t.Fatal(err)
	}
	if warehouse.satelCalls != 2 || warehouse.satelRows != 7 {
		t.Fatalf("replayed calls=%d rows=%d, want 2/7",
			warehouse.satelCalls, warehouse.satelRows)
	}
	valid, err := control.IngestFile(ctx, device.ID, fileIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	quarantined, err := control.IngestFile(ctx, device.ID, fileIDs[1])
	if err != nil {
		t.Fatal(err)
	}
	if valid.ReplayState != "complete" || valid.Status != "processed" ||
		valid.ParserVersion != analytics.SatelRTUParserVersion {
		t.Fatalf("valid replay ledger = %#v", valid)
	}
	if quarantined.ReplayState != "complete" || quarantined.Status != "quarantined" ||
		quarantined.RowsTotal != 4 || quarantined.RowsValid != 3 ||
		quarantined.ParserVersion != analytics.SatelRTUParserVersion {
		t.Fatalf("partial replay ledger = %#v", quarantined)
	}
	newUploadPath := filepath.Join(t.TempDir(), "new-satel.csv")
	if err := os.WriteFile(newUploadPath, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	newUploadInfo, err := os.Stat(newUploadPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.process(ctx, device, newUploadPath, newUploadInfo); err != nil {
		t.Fatal(err)
	}
	ledger, err := control.ListRecentIngestFiles(ctx, device.ID, 20)
	if err != nil {
		t.Fatal(err)
	}
	foundNewUpload := false
	for _, item := range ledger {
		if item.OriginalName == "new-satel.csv" {
			foundNewUpload = true
			if item.ParserTemplate != equipment.TemplateSatelRTUCDRV1 ||
				item.ParserVersion != analytics.SatelRTUParserVersion ||
				item.Status != "processed" {
				t.Fatalf("new Satel upload provenance = %#v", item)
			}
		}
	}
	if !foundNewUpload {
		t.Fatal("new Satel upload missing from ingest ledger")
	}
	restartedAnalytics := &countingCDRAnalytics{}
	restarted := &CDRWatcher{
		Store: control, Analytics: restartedAnalytics, Archive: memoryArchive,
	}
	if err := restarted.drainIngestReplays(ctx, 100); err != nil {
		t.Fatal(err)
	}
	if restartedAnalytics.satelCalls != 0 {
		t.Fatalf("completed replay reran %d batches after restart", restartedAnalytics.satelCalls)
	}
}
