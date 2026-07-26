package analytics

import (
	"testing"
	"time"
)

func TestLocalRFC3339UsesDeviceTimezone(t *testing.T) {
	value := time.Date(2026, time.July, 26, 15, 5, 9, 123_000_000, time.UTC)
	if got := localRFC3339(&value, "UTC"); got != "2026-07-26T15:05:09.123Z" {
		t.Fatalf("UTC = %q", got)
	}
	if got := localRFC3339(&value, "Europe/Moscow"); got != "2026-07-26T18:05:09.123+03:00" {
		t.Fatalf("Europe/Moscow = %q", got)
	}
}

func TestLocalRFC3339HonorsDaylightSavingTime(t *testing.T) {
	winter := time.Date(2026, time.January, 15, 12, 0, 0, 0, time.UTC)
	summer := time.Date(2026, time.July, 15, 12, 0, 0, 0, time.UTC)
	if got := localRFC3339(&winter, "Europe/Berlin"); got != "2026-01-15T13:00:00+01:00" {
		t.Fatalf("winter = %q", got)
	}
	if got := localRFC3339(&summer, "Europe/Berlin"); got != "2026-07-15T14:00:00+02:00" {
		t.Fatalf("summer = %q", got)
	}
}
