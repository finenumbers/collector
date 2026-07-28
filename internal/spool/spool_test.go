package spool

import (
	"path/filepath"
	"testing"
	"time"
)

func TestQueuePersistsAndDeletesInOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syslog.db")
	queue, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := queue.EnqueueBatch([]Entry{
		{ReceivedAt: now, EventID: "first", Payload: []byte("one")},
		{ReceivedAt: now.Add(time.Nanosecond), EventID: "second", Payload: []byte("two")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	queue, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	items, err := queue.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || string(items[0].Data) != "one" || string(items[1].Data) != "two" {
		t.Fatalf("unexpected persisted items: %#v", items)
	}
	if err := queue.Delete([][]byte{items[0].Key}); err != nil {
		t.Fatal(err)
	}
	depth, err := queue.Depth()
	if err != nil {
		t.Fatal(err)
	}
	if depth != 1 {
		t.Fatalf("got depth %d, want 1", depth)
	}
}

func TestQueueQuarantinesWithoutDiscardingPayload(t *testing.T) {
	queue, err := Open(filepath.Join(t.TempDir(), "syslog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	if err := queue.EnqueueBatch([]Entry{{
		ReceivedAt: time.Now().UTC(), EventID: "broken", Payload: []byte{0xff, 0x00, 0x01},
	}}); err != nil {
		t.Fatal(err)
	}
	items, err := queue.Peek(1)
	if err != nil || len(items) != 1 {
		t.Fatalf("unable to read queued item: %#v, %v", items, err)
	}
	if err := queue.Quarantine(items[0].Key, items[0].Data, "invalid envelope"); err != nil {
		t.Fatal(err)
	}
	depth, err := queue.Depth()
	if err != nil || depth != 0 {
		t.Fatalf("got queue depth %d, want 0: %v", depth, err)
	}
	quarantineDepth, err := queue.QuarantineDepth()
	if err != nil || quarantineDepth != 1 {
		t.Fatalf("got quarantine depth %d, want 1: %v", quarantineDepth, err)
	}
}

func TestQueueEnqueuesBatchAtomically(t *testing.T) {
	queue, err := Open(filepath.Join(t.TempDir(), "syslog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	now := time.Now().UTC()
	if err := queue.EnqueueBatch([]Entry{
		{ReceivedAt: now, EventID: "first", Payload: []byte("one")},
		{ReceivedAt: now.Add(time.Nanosecond), EventID: "second", Payload: []byte("two")},
		{ReceivedAt: now.Add(2 * time.Nanosecond), EventID: "third", Payload: []byte("three")},
	}); err != nil {
		t.Fatal(err)
	}
	items, err := queue.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || string(items[0].Data) != "one" ||
		string(items[1].Data) != "two" || string(items[2].Data) != "three" {
		t.Fatalf("unexpected batch contents: %#v", items)
	}
}

func TestQueueDeleteMatchingPurgesMainAndQuarantine(t *testing.T) {
	queue, err := Open(filepath.Join(t.TempDir(), "syslog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	now := time.Now().UTC()
	if err := queue.EnqueueBatch([]Entry{
		{ReceivedAt: now, EventID: "purge-main", Payload: []byte("device-a/main")},
		{ReceivedAt: now.Add(time.Nanosecond), EventID: "purge-quarantine", Payload: []byte("device-a/quarantine")},
		{ReceivedAt: now.Add(2 * time.Nanosecond), EventID: "keep", Payload: []byte("device-b/main")},
	}); err != nil {
		t.Fatal(err)
	}
	items, err := queue.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.Quarantine(items[1].Key, items[1].Data, "test"); err != nil {
		t.Fatal(err)
	}
	deleted, err := queue.DeleteMatching(func(payload []byte) bool {
		return len(payload) >= len("device-a") && string(payload[:len("device-a")]) == "device-a"
	})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted %d entries, want 2", deleted)
	}
	depth, err := queue.Depth()
	if err != nil || depth != 1 {
		t.Fatalf("main depth %d, want 1: %v", depth, err)
	}
	quarantineDepth, err := queue.QuarantineDepth()
	if err != nil || quarantineDepth != 0 {
		t.Fatalf("quarantine depth %d, want 0: %v", quarantineDepth, err)
	}
}

func TestSourceFenceAtomicallyRejectsLateIngress(t *testing.T) {
	queue, err := Open(filepath.Join(t.TempDir(), "syslog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	source := func(payload []byte) string { return string(payload) }
	if _, err := queue.BlockSourceAndDelete("device-a", func(payload []byte) bool {
		return string(payload) == "device-a"
	}); err != nil {
		t.Fatal(err)
	}
	accepted, err := queue.EnqueueBatchWithSourceFence([]Entry{
		{ReceivedAt: time.Now(), EventID: "blocked", Payload: []byte("device-a")},
		{ReceivedAt: time.Now(), EventID: "allowed", Payload: []byte("device-b")},
	}, source)
	if err != nil {
		t.Fatal(err)
	}
	if accepted != 1 {
		t.Fatalf("accepted %d entries, want 1", accepted)
	}
	if err := queue.UnblockSource("device-a"); err != nil {
		t.Fatal(err)
	}
	accepted, err = queue.EnqueueBatchWithSourceFence([]Entry{{
		ReceivedAt: time.Now(), EventID: "reused", Payload: []byte("device-a"),
	}}, source)
	if err != nil || accepted != 1 {
		t.Fatalf("reused source accepted=%d, error=%v", accepted, err)
	}
}
