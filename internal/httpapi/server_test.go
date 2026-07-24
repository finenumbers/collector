package httpapi

import (
	"testing"

	"collector/internal/analytics"
)

func TestRevisionDiagnosticsAreIncludedInAPIResponse(t *testing.T) {
	response := make(map[string]any)
	addRevisionDiagnostics(response, analytics.SyslogDiagnostics{
		ActiveRevision: 1, BuildingRevision: 2, RevisionTimezone: "Asia/Novosibirsk",
		RevisionStatus: "building", ReplayProcessed: 10, ReplayTotal: 20,
		CDRReplayProcessed: 3, CDRReplayTotal: 4, MissingCDRTimes: 1,
		RadiusRawFragments: 30, LifecycleDerived: 12, CorrelationTotal: 12,
		CorrelationOrphan: 2,
	})
	required := []string{
		"activeRevision", "buildingRevision", "revisionTimezone", "revisionStatus",
		"replayProcessed", "replayTotal", "cdrReplayProcessed", "cdrReplayTotal",
		"missingCdrInterpretations", "radiusRawFragments", "lifecycleDerived",
		"correlationTotal", "correlationOrphan",
	}
	for _, key := range required {
		if _, ok := response[key]; !ok {
			t.Fatalf("diagnostics response is missing %q", key)
		}
	}
}
