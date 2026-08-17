package syslogarchive

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const SlotDuration = 10 * time.Minute

// RawRetentionAfterHourEnd is the minimum time raw syslog for a closed UTC hour
// stays in ClickHouse so AntiFraud tails (pairing, late NATS, CDR expected/late)
// can still catch up.
const RawRetentionAfterHourEnd = 2 * time.Hour

var deviceSignPattern = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

var (
	tenMinuteArchiveName = regexp.MustCompile(`_[0-9]{2}-[0-9]{2}\.zip$`)
	hourlyArchiveName    = regexp.MustCompile(`_[0-9]{2}\.zip$`)
)

func SanitizeDeviceSign(sign string) string {
	sign = strings.ToLower(strings.TrimSpace(sign))
	sign = deviceSignPattern.ReplaceAllString(sign, "")
	sign = strings.Trim(sign, "_-")
	return sign
}

// ArchiveName builds {sign}_{DD.MM.YYYY}_{HH-mm}.zip for slotStart in loc.
func ArchiveName(deviceSign string, slotStart time.Time, loc *time.Location) (string, error) {
	sign := SanitizeDeviceSign(deviceSign)
	if sign == "" {
		return "", fmt.Errorf("deviceSign is empty or invalid")
	}
	if loc == nil {
		loc = time.UTC
	}
	local := slotStart.In(loc)
	return fmt.Sprintf("%s_%02d.%02d.%04d_%02d-%02d.zip",
		sign, local.Day(), int(local.Month()), local.Year(), local.Hour(), local.Minute()), nil
}

// IsLegacyHourlyArchiveName reports leftover hourly `{sign}_{DD.MM.YYYY}_{HH}.zip`.
func IsLegacyHourlyArchiveName(name string) bool {
	return hourlyArchiveName.MatchString(name) && !tenMinuteArchiveName.MatchString(name)
}

// TruncateSlot returns the 10-minute slot start containing t in loc.
func TruncateSlot(t time.Time, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	local := t.In(loc)
	minute := (local.Minute() / 10) * 10
	return time.Date(local.Year(), local.Month(), local.Day(),
		local.Hour(), minute, 0, 0, loc)
}

// ClosedSlotStart returns the start of the last fully closed 10-minute slot
// in loc, after applying closeDelay from now.
func ClosedSlotStart(now time.Time, loc *time.Location, closeDelay time.Duration) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	if closeDelay < 0 {
		closeDelay = 0
	}
	effective := now.Add(-closeDelay).In(loc)
	return TruncateSlot(effective, loc).Add(-SlotDuration)
}

// SlotBoundsUTC returns [start,end) in UTC for a local slot start.
func SlotBoundsUTC(slotStartLocal time.Time) (time.Time, time.Time) {
	start := slotStartLocal
	end := slotStartLocal.Add(SlotDuration)
	return start.UTC(), end.UTC()
}

// UTCHourStart truncates t to a UTC hour.
func UTCHourStart(t time.Time) time.Time {
	return t.UTC().Truncate(time.Hour)
}

// RawDeleteCutoff returns the exclusive upper bound for a one-shot historical
// purge: hours that ended at least RawRetentionAfterHourEnd ago.
func RawDeleteCutoff(now time.Time) time.Time {
	return now.UTC().Truncate(time.Hour).Add(-RawRetentionAfterHourEnd)
}

// HourMayDelete reports whether the UTC hour [hourStart, hourStart+1h) is old
// enough that raw syslog may be removed (time gate only).
func HourMayDelete(now, hourStart time.Time) bool {
	hourEnd := hourStart.UTC().Truncate(time.Hour).Add(time.Hour)
	return !now.UTC().Before(hourEnd.Add(RawRetentionAfterHourEnd))
}

// SlotOverlapsUTCHour reports whether [slotStart, slotStart+10m) overlaps
// the half-open UTC hour [hourStart, hourStart+1h).
func SlotOverlapsUTCHour(slotStart, hourStart time.Time) bool {
	from, to := SlotBoundsUTC(slotStart)
	hour := hourStart.UTC().Truncate(time.Hour)
	hourEnd := hour.Add(time.Hour)
	return from.Before(hourEnd) && to.After(hour)
}
