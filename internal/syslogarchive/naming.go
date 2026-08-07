package syslogarchive

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var deviceSignPattern = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func SanitizeDeviceSign(sign string) string {
	sign = strings.ToLower(strings.TrimSpace(sign))
	sign = deviceSignPattern.ReplaceAllString(sign, "")
	sign = strings.Trim(sign, "_-")
	return sign
}

// ArchiveName builds {sign}_{DD.MM.YYYY}_{HH}.zip for hourStart in loc.
func ArchiveName(deviceSign string, hourStart time.Time, loc *time.Location) (string, error) {
	sign := SanitizeDeviceSign(deviceSign)
	if sign == "" {
		return "", fmt.Errorf("deviceSign is empty or invalid")
	}
	if loc == nil {
		loc = time.UTC
	}
	local := hourStart.In(loc)
	return fmt.Sprintf("%s_%02d.%02d.%04d_%02d.zip",
		sign, local.Day(), int(local.Month()), local.Year(), local.Hour()), nil
}

// ClosedHourStart returns the start of the last fully closed hour in loc,
// after applying closeDelay from now.
func ClosedHourStart(now time.Time, loc *time.Location, closeDelay time.Duration) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	effective := now.Add(-closeDelay).In(loc)
	truncated := time.Date(effective.Year(), effective.Month(), effective.Day(),
		effective.Hour(), 0, 0, 0, loc)
	return truncated.Add(-time.Hour)
}

// HourBoundsUTC returns [start,end) in UTC for a local hour start.
func HourBoundsUTC(hourStartLocal time.Time) (time.Time, time.Time) {
	start := hourStartLocal
	end := hourStartLocal.Add(time.Hour)
	return start.UTC(), end.UTC()
}
