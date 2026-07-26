package store

import (
	"testing"
	"time"
)

func TestRetentionScheduling(t *testing.T) {
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	for _, days := range []int{7, 14, 60, 1095} {
		effective, err := retentionEffectiveAt(now, days)
		if err != nil || !effective.Equal(now) {
			t.Fatalf("days=%d was not immediate: %v, %v", days, effective, err)
		}
	}
	for _, days := range []int{6, 1096} {
		if _, err := retentionEffectiveAt(now, days); err == nil {
			t.Fatalf("invalid retention %d was accepted", days)
		}
	}
}
