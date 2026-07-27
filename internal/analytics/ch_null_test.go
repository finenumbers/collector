package analytics

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestChUUIDPtrNilIsUntypedNil(t *testing.T) {
	if chUUIDPtr(nil) != nil {
		t.Fatal("expected untyped nil")
	}
	nilID := uuid.Nil
	if chUUIDPtr(&nilID) != nil {
		t.Fatal("expected nil for uuid.Nil")
	}
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	got, ok := chUUIDPtr(&id).(uuid.UUID)
	if !ok || got != id {
		t.Fatalf("got %#v", chUUIDPtr(&id))
	}
}

func TestChTimeHelpers(t *testing.T) {
	if chTimePtr(nil) != nil || chTime(time.Time{}) != nil {
		t.Fatal("expected nil")
	}
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	if chTime(now) != now {
		t.Fatalf("got %#v", chTime(now))
	}
}
