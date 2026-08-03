package customprojection

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAdvanceEmptyBucketWatermarkKeepsEventTip(t *testing.T) {
	eventTime := time.Date(2026, 8, 3, 4, 0, 0, 0, time.UTC)
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	gotTime, gotID := AdvanceEmptyBucketWatermark(
		eventTime, id,
		time.Date(2026, 8, 3, 5, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 3, 6, 0, 0, 0, time.UTC),
	)
	if !gotTime.Equal(eventTime) || gotID != id {
		t.Fatalf("got %s %s, want event tip kept", gotTime, gotID)
	}
}

func TestAdvanceEmptyBucketWatermarkClosedHour(t *testing.T) {
	bucketEnd := time.Date(2026, 8, 3, 5, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 3, 6, 30, 0, 0, time.UTC)
	gotTime, gotID := AdvanceEmptyBucketWatermark(time.Time{}, uuid.Nil, bucketEnd, now)
	if !gotTime.Equal(bucketEnd) {
		t.Fatalf("got %s, want bucket end", gotTime)
	}
	if gotID != uuid.Nil {
		t.Fatalf("empty advance id = %s, want nil", gotID)
	}
}

func TestAdvanceEmptyBucketWatermarkOpenHourClampsNow(t *testing.T) {
	bucketEnd := time.Date(2026, 8, 3, 7, 0, 0, 0, time.UTC)
	now := time.Date(2026, 8, 3, 6, 30, 0, 0, time.UTC)
	gotTime, _ := AdvanceEmptyBucketWatermark(time.Time{}, uuid.Nil, bucketEnd, now)
	if !gotTime.Equal(now) {
		t.Fatalf("got %s, want now clamp", gotTime)
	}
}
