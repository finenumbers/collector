package syslogarchive

import (
	"strings"
	"testing"
	"time"
)

func TestArchiveNameTenMinuteSlot(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Novosibirsk")
	if err != nil {
		t.Fatal(err)
	}
	slot := time.Date(2026, 7, 22, 22, 10, 0, 0, loc)
	name, err := ArchiveName("MTS", slot, loc)
	if err != nil {
		t.Fatal(err)
	}
	if name != "mts_22.07.2026_22-10.zip" {
		t.Fatalf("got %q", name)
	}
	if strings.Contains(name, ":") {
		t.Fatal("archive name must not contain a colon")
	}
}

func TestArchiveNameAllSlotsInHour(t *testing.T) {
	loc := time.UTC
	hour := time.Date(2026, 8, 17, 14, 0, 0, 0, loc)
	want := []string{
		"mts_17.08.2026_14-00.zip",
		"mts_17.08.2026_14-10.zip",
		"mts_17.08.2026_14-20.zip",
		"mts_17.08.2026_14-30.zip",
		"mts_17.08.2026_14-40.zip",
		"mts_17.08.2026_14-50.zip",
	}
	for i, name := range want {
		slot := hour.Add(time.Duration(i) * SlotDuration)
		got, err := ArchiveName("MTS", slot, loc)
		if err != nil {
			t.Fatal(err)
		}
		if got != name {
			t.Fatalf("slot %d: got %q want %q", i, got, name)
		}
	}
}

func TestSanitizeDeviceSign(t *testing.T) {
	if got := SanitizeDeviceSign(" MTS-01! "); got != "mts-01" {
		t.Fatalf("got %q", got)
	}
}

func TestArchiveNameRejectsEmptySign(t *testing.T) {
	if _, err := ArchiveName("!!!", time.Now(), time.UTC); err == nil {
		t.Fatal("expected empty sign error")
	}
}

func TestIsLegacyHourlyArchiveName(t *testing.T) {
	if !IsLegacyHourlyArchiveName("fixer_17.08.2026_14.zip") {
		t.Fatal("hourly leftover should match")
	}
	if IsLegacyHourlyArchiveName("fixer_17.08.2026_14-00.zip") {
		t.Fatal("ten-minute name must not match")
	}
}

func TestClosedSlotStart(t *testing.T) {
	loc := time.FixedZone("test", 7*3600)
	now := time.Date(2026, 7, 22, 15, 11, 0, 0, loc)
	got := ClosedSlotStart(now, loc, time.Minute)
	want := time.Date(2026, 7, 22, 15, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	stillOpen := ClosedSlotStart(now, loc, 2*time.Minute)
	wantOpen := time.Date(2026, 7, 22, 14, 50, 0, 0, loc)
	if !stillOpen.Equal(wantOpen) {
		t.Fatalf("open slot: got %v want %v", stillOpen, wantOpen)
	}
}

func TestSlotBoundsDoesNotZeroMinutes(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Novosibirsk")
	if err != nil {
		t.Fatal(err)
	}
	slot := time.Date(2026, 8, 17, 14, 10, 0, 0, loc)
	from, to := SlotBoundsUTC(slot)
	if to.Sub(from) != SlotDuration {
		t.Fatalf("window %s", to.Sub(from))
	}
	if from.Equal(slot.UTC().Truncate(time.Hour)) {
		t.Fatal("slot start must keep minutes")
	}
}

func TestHourMayDeleteTwoHoursAfterEnd(t *testing.T) {
	hour := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	if HourMayDelete(time.Date(2026, 8, 17, 16, 59, 0, 0, time.UTC), hour) {
		t.Fatal("must keep hour until 17:00")
	}
	if !HourMayDelete(time.Date(2026, 8, 17, 17, 0, 0, 0, time.UTC), hour) {
		t.Fatal("17:00 must allow delete")
	}
}

func TestSlotOverlapsUTCHour(t *testing.T) {
	hour := time.Date(2026, 8, 17, 14, 0, 0, 0, time.UTC)
	if SlotOverlapsUTCHour(hour.Add(-10*time.Minute), hour) {
		t.Fatal("13:50-14:00 must not overlap hour 14")
	}
	if !SlotOverlapsUTCHour(hour, hour) {
		t.Fatal("14:00-14:10 must overlap hour 14")
	}
	if !SlotOverlapsUTCHour(hour.Add(50*time.Minute), hour) {
		t.Fatal("14:50-15:00 must overlap hour 14")
	}
	if SlotOverlapsUTCHour(hour.Add(time.Hour), hour) {
		t.Fatal("15:00-15:10 must not overlap hour 14")
	}
}

func TestRawDeleteCutoff(t *testing.T) {
	now := time.Date(2026, 8, 17, 17, 10, 0, 0, time.UTC)
	got := RawDeleteCutoff(now)
	want := time.Date(2026, 8, 17, 15, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
