package syslogarchive

import (
	"os"
	"strings"
	"testing"
)

func TestWorkerUsesTenMinuteSlots(t *testing.T) {
	body, err := os.ReadFile("worker.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(body)
	if strings.Contains(source, "ClosedHourStart") || strings.Contains(source, "HourBoundsUTC") {
		t.Fatal("hourly archive helpers must not remain in the worker")
	}
	if !strings.Contains(source, "ClosedSlotStart") || !strings.Contains(source, "SlotBoundsUTC") {
		t.Fatal("worker must enqueue and export 10-minute slots")
	}
	if !strings.Contains(source, "tmp.Sync()") {
		t.Fatal("ZIP files must be fsynced before rename")
	}
	if !strings.Contains(source, "maxArchiveBuildsPerTick") {
		t.Fatal("pending ZIP builds must be rate-limited per tick")
	}
	if !strings.Contains(source, "livenessLoop") {
		t.Fatal("worker process must heartbeat independently of tick duration")
	}
}
