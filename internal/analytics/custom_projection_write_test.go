package analytics

import (
	"testing"
	"time"

	"collector/internal/customprojection"
	"collector/internal/customradius"

	"github.com/google/uuid"
)

func TestCallPacketLinkIDsSkipPacketsMissingFromSnapshot(t *testing.T) {
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
	missingFromResult := customradius.Packet{
		ID: uuid.New(), FirstSeenAt: bucket.Add(4 * time.Minute), LastSeenAt: bucket.Add(4 * time.Minute),
	}
	snapshot := customprojection.Snapshot{
		BucketStart: bucket,
		Result: customradius.Result{
			Packets: []customradius.Packet{inHour, alsoInHour, outsideHour},
			Calls: []customradius.Call{{
				ID: uuid.New(),
				Packets: []customradius.Packet{inHour, missingFromResult, alsoInHour, outsideHour},
			}},
		},
	}
	got := callPacketLinkIDs(snapshot, snapshot.Result.Calls[0])
	if len(got) != 2 || got[0] != inHour.ID || got[1] != alsoInHour.ID {
		t.Fatalf("links=%v want [%s %s]", got, inHour.ID, alsoInHour.ID)
	}
}
