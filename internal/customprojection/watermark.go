package customprojection

import (
	"time"

	"github.com/google/uuid"
)

// AdvanceEmptyBucketWatermark moves the device tip through a successfully
// processed hour that had no AF/RADIUS events, so quiet SMGs do not freeze
// watermark_received_at on the last historical call forever.
func AdvanceEmptyBucketWatermark(
	watermarkTime time.Time, watermarkID uuid.UUID, bucketEnd, now time.Time,
) (time.Time, uuid.UUID) {
	if !watermarkTime.IsZero() {
		return watermarkTime, watermarkID
	}
	advanced := bucketEnd.UTC()
	now = now.UTC()
	if advanced.After(now) {
		advanced = now
	}
	return advanced, uuid.Nil
}
