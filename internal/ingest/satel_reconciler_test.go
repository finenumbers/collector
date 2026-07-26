package ingest

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"collector/internal/archive"
	"collector/internal/store"

	"github.com/google/uuid"
)

type fakeSatelDetectionStore struct {
	samples     []store.ImmutableIngestObject
	status      string
	message     string
	fingerprint string
	activated   bool
	locked      bool
}

func (fake *fakeSatelDetectionStore) RawDevicesNeedingDetection(
	context.Context,
) ([]store.Device, error) {
	return nil, nil
}

func (fake *fakeSatelDetectionStore) RecentImmutableIngestObjects(
	context.Context, uuid.UUID, int,
) ([]store.ImmutableIngestObject, error) {
	return fake.samples, nil
}

func (fake *fakeSatelDetectionStore) RecordTemplateDetection(
	_ context.Context, _ uuid.UUID, status, _, fingerprint, message string, _ *time.Time,
) error {
	fake.status, fake.fingerprint, fake.message = status, fingerprint, message
	return nil
}

func (fake *fakeSatelDetectionStore) ActivateDetectedSatel(
	context.Context, uuid.UUID, string, time.Time,
) error {
	fake.activated = true
	return nil
}

func (fake *fakeSatelDetectionStore) LockDeviceWrites(uuid.UUID) func() {
	fake.locked = true
	return func() { fake.locked = false }
}

type lockCheckingArchive struct {
	store   *fakeSatelDetectionStore
	objects map[string][]byte
	t       *testing.T
}

func (fake *lockCheckingArchive) Put(
	context.Context, string, io.Reader, int64, string,
) error {
	return nil
}

func (fake *lockCheckingArchive) OpenObject(
	_ context.Context, key string,
) (archive.Object, error) {
	if !fake.store.locked {
		fake.t.Fatal("archive sample opened outside device write lock")
	}
	content := fake.objects[key]
	return archive.Object{Reader: io.NopCloser(bytes.NewReader(content))}, nil
}

func TestRawSatelDetectionRejectsMixedRecentSamples(t *testing.T) {
	exact, err := os.ReadFile("testdata/satel_rtu_cdr.csv")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	database := &fakeSatelDetectionStore{samples: []store.ImmutableIngestObject{
		{ID: uuid.New(), ObjectKey: "exact", ReceivedAt: now},
		{ID: uuid.New(), ObjectKey: "other", ReceivedAt: now.Add(-time.Minute)},
	}}
	objects := &lockCheckingArchive{
		store: database, t: t,
		objects: map[string][]byte{
			"exact": exact,
			"other": []byte("cdr_id;cdr_date;setup_time\n1;2;3\n"),
		},
	}
	if err := reconcileRawSatelDevice(
		context.Background(), database, objects, uuid.New(),
	); err != nil {
		t.Fatal(err)
	}
	if database.status != "mixed" || database.message == "" ||
		database.activated || database.locked {
		t.Fatalf("mixed detection state = %#v", database)
	}
}
