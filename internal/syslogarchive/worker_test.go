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
	if !strings.Contains(source, "errArchiveAbandoned") {
		t.Fatal("sealed-hour abandon must be a sentinel, not a tick last_error")
	}
	if !strings.Contains(source, "slotUTCHoursBlocked") {
		t.Fatal("enqueue must skip slots whose UTC hour is already sealed")
	}
	if !strings.Contains(source, "errors.Is(err, errArchiveAbandoned)") {
		t.Fatal("processOne must treat abandon as success for the worker tick")
	}
}

func TestHideWorkerLastError(t *testing.T) {
	if !HideWorkerLastError("utc hour sealed") {
		t.Fatal("exact sealed reason must be hidden on the worker line")
	}
	if !HideWorkerLastError("archive job abandoned: utc hour sealed") {
		t.Fatal("wrapped sealed reason must be hidden on the worker line")
	}
	if HideWorkerLastError("ftp not configured") {
		t.Fatal("real FTP errors must stay on the worker line")
	}
	if HideWorkerLastError("") {
		t.Fatal("empty last_error is not an operational abandon")
	}
}
