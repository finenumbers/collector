package httpapi

import (
	"testing"
	"time"

	"collector/internal/syslogarchive"
)

func TestLiveArchiveLagUsesClosedSlotNotLookback(t *testing.T) {
	loc := time.UTC
	now := time.Date(2026, 8, 17, 15, 22, 0, 0, loc)
	closeDelay := 2 * time.Minute
	cutoff := syslogarchive.RawDeleteCutoff(now)
	closed := syslogarchive.ClosedSlotStart(now, loc, closeDelay)
	if lag := liveArchiveLag(now, loc, closeDelay, cutoff, &closed); lag != 0 {
		t.Fatalf("current closed slot uploaded: lag=%s", lag)
	}
	previous := closed.Add(-syslogarchive.SlotDuration)
	if lag := liveArchiveLag(now, loc, closeDelay, cutoff, &previous); lag != syslogarchive.SlotDuration {
		t.Fatalf("one slot behind: lag=%s", lag)
	}
	if lag := liveArchiveLag(now, loc, closeDelay, cutoff, nil); lag <= 0 {
		t.Fatal("missing uploads must report positive live-window lag")
	}
}
