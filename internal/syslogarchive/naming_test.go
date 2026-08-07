package syslogarchive

import (
	"testing"
	"time"
)

func TestArchiveName(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Novosibirsk")
	if err != nil {
		t.Fatal(err)
	}
	// 22:00 local on 22.07.2026
	hour := time.Date(2026, 7, 22, 22, 0, 0, 0, loc)
	name, err := ArchiveName("MTS", hour, loc)
	if err != nil {
		t.Fatal(err)
	}
	if name != "mts_22.07.2026_22.zip" {
		t.Fatalf("got %q", name)
	}
}

func TestSanitizeDeviceSign(t *testing.T) {
	if got := SanitizeDeviceSign(" MTS-01! "); got != "mts-01" {
		t.Fatalf("got %q", got)
	}
	if _, err := ArchiveName("!!!", time.Now(), time.UTC); err == nil {
		t.Fatal("expected empty sign error")
	}
}

func TestClosedHourStart(t *testing.T) {
	loc := time.FixedZone("test", 7*3600)
	now := time.Date(2026, 7, 22, 15, 3, 0, 0, loc) // 15:03
	got := ClosedHourStart(now, loc, 2*time.Minute)
	// effective 15:01 → current hour 15 → closed 14:00
	want := time.Date(2026, 7, 22, 14, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
