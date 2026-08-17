package syslogarchive

import (
	"testing"
	"time"
)

func TestHourGCGatesKeepOpenHour(t *testing.T) {
	hour := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 17, 16, 59, 0, 0, time.UTC)
	if hourGCGatesReady(now, hour, true, true, 10, 0, 6, true, true, 0) {
		t.Fatal("must not delete before hourEnd+2h")
	}
}

func TestHourGCGatesNeedNextHourAndCoverage(t *testing.T) {
	hour := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 17, 17, 0, 0, 0, time.UTC)
	if hourGCGatesReady(now, hour, true, true, 10, 0, 6, true, false, 0) {
		t.Fatal("must wait for AF hour H+1")
	}
	if hourGCGatesReady(now, hour, true, true, 10, 0, 6, true, true, 3) {
		t.Fatal("must keep raw while CDR coverage is expected/late")
	}
	if hourGCGatesReady(now, hour, false, true, 10, 0, 6, true, true, 0) {
		t.Fatal("hourly GC is off when archive is disabled")
	}
	if hourGCGatesReady(now, hour, true, true, 10, 1, 5, true, true, 0) {
		t.Fatal("pending ZIP jobs must block delete")
	}
	if hourGCGatesReady(now, hour, true, true, 10, 0, 0, true, true, 0) {
		t.Fatal("raw with no ZIP must not be deleted")
	}
	if !hourGCGatesReady(now, hour, true, true, 10, 0, 6, true, true, 0) {
		t.Fatal("expected all gates to pass")
	}
	if !hourGCGatesReady(now, hour, true, false, 10, 0, 0, true, true, 0) {
		t.Fatal("device without archive may delete after AF gates")
	}
}

func TestHourGCGatesAllowEmptyHourWithoutZIP(t *testing.T) {
	hour := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 17, 17, 0, 0, 0, time.UTC)
	if !hourGCGatesReady(now, hour, true, true, 0, 0, 0, true, true, 0) {
		t.Fatal("empty GC'd hour should not require ZIP")
	}
}
