package store

import (
	"testing"
	"time"
)

func TestRetentionScheduling(t *testing.T) {
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	immediate, err := retentionEffectiveAt(now, 30, 60, false)
	if err != nil || !immediate.Equal(now) {
		t.Fatalf("increase was not immediate: %v, %v", immediate, err)
	}
	if _, err := retentionEffectiveAt(now, 30, 14, false); err == nil {
		t.Fatal("unconfirmed decrease was accepted")
	}
	delayed, err := retentionEffectiveAt(now, 30, 14, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(7 * 24 * time.Hour); !delayed.Equal(want) {
		t.Fatalf("decrease effective at %v, want %v", delayed, want)
	}
	for _, days := range []int{6, 1096} {
		if _, err := retentionEffectiveAt(now, 30, days, true); err == nil {
			t.Fatalf("invalid retention %d was accepted", days)
		}
	}
}
