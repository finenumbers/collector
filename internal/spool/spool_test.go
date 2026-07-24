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
	if err := queue.Enqueue(now, "first", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := queue.Enqueue(now.Add(time.Nanosecond), "second", []byte("two")); err != nil {
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
