package analytics

import (
	"testing"
	"time"

	"collector/internal/customprojection"
	"collector/internal/customradius"

	"github.com/google/uuid"
)

func TestSnapshotPacketIDsInBucketSkipsOutsideHour(t *testing.T) {
	bucket := time.Date(2026, 7, 28, 16, 0, 0, 0, time.UTC)
	inHour := customradius.Packet{
		ID: uuid.New(), FirstSeenAt: bucket.Add(2 * time.Minute), LastSeenAt: bucket.Add(2 * time.Minute),
	}
	alsoInHour := customradius.Packet{
		ID: uuid.New(), FirstSeenAt: bucket.Add(3 * time.Minute), LastSeenAt: bucket.Add(3 * time.Minute),
	}
	outsideHour := customradius.Packet{
		ID: uuid.New(), FirstSeenAt: bucket.Add(-time.Minute), LastSeenAt: bucket.Add(-time.Minute),
	}
	snapshot := customprojection.Snapshot{
		BucketStart: bucket,
		Result: customradius.Result{
			Packets: []customradius.Packet{inHour, alsoInHour, outsideHour},
		},
	}
	got := snapshotPacketIDsInBucket(snapshot)
	if len(got) != 2 {
		t.Fatalf("packet ids=%d want 2", len(got))
	}
	if _, ok := got[inHour.ID]; !ok {
		t.Fatal("missing in-hour packet")
	}
	if _, ok := got[alsoInHour.ID]; !ok {
		t.Fatal("missing second in-hour packet")
	}
	if _, ok := got[outsideHour.ID]; ok {
		t.Fatal("outside-hour packet must not be written")
	}
}
