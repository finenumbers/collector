package analytics

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSafeOrderedAttributesRedactsSecretsAndKeepsOrder(t *testing.T) {
	attributes := safeOrderedAttributes(`[
		{"name":"Calling-Station-Id","value":"70000000000"},
		{"name":"shared-secret","value":"do-not-export"},
		{"name":"nested","value":{"auth_token":"do-not-export","decision":"accept"}}
	]`)
	if len(attributes) != 3 {
		t.Fatalf("attributes=%#v", attributes)
	}
	if attributes[0].Name != "Calling-Station-Id" || attributes[1].Name != "shared-secret" {
		t.Fatalf("attribute order changed: %#v", attributes)
	}
	if attributes[1].Value != "[REDACTED]" {
		t.Fatalf("secret was exported: %#v", attributes[1])
	}
	nested, ok := attributes[2].Value.(map[string]any)
	if !ok || nested["auth_token"] != "[REDACTED]" || nested["decision"] != "accept" {
		t.Fatalf("nested redaction failed: %#v", attributes[2].Value)
	}
}

func TestSafeJSONValueRejectsRawNonJSONPayload(t *testing.T) {
	if got := safeJSONValue(`User-Password=secret`); got != nil {
		t.Fatalf("raw payload escaped JSON boundary: %#v", got)
	}
}

func TestOrderedFamiliesAndCompleteness(t *testing.T) {
	phases := orderedFamilies([]string{"accounting", "unknown", "indication", "verification", "indication"})
	if strings.Join(phases, ",") != "indication,verification,accounting" {
		t.Fatalf("phases=%v", phases)
	}
	complete := chainCompletenessFromSummary(phases, 0, 0, "completed")
	if complete.State != "complete" {
		t.Fatalf("complete=%+v", complete)
	}
	partial := chainCompletenessFromSummary([]string{"indication"}, 1, 0, "pending")
	if partial.State != "partial" && partial.State != "minimal" {
		t.Fatalf("partial=%+v", partial)
	}
	if deriveAFCoverageState(true, false, time.Now().UTC(), time.Now().UTC()) != "matched" {
		t.Fatal("matched coverage")
	}
	if deriveAFCoverageState(false, false, time.Now().UTC().Add(-40*time.Minute), time.Now().UTC()) != "missing" {
		t.Fatal("missing coverage")
	}
}

func TestBuildTimelinePairsRequestResponse(t *testing.T) {
	requestID := mustParseUUID("11111111-1111-4111-8111-111111111111")
	responseID := mustParseUUID("22222222-2222-4222-8222-222222222222")
	base := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	events := buildTimeline([]AntifraudPacket{
		{
			PacketID: requestID, FirstSeenAt: base, Family: "indication",
			RadiusType: "access-request", Direction: "request", Status: "paired",
			ResponseID: &responseID,
			Attributes: []OrderedAttribute{{Name: "xpgk-request-type", Value: "number"}},
		},
		{
			PacketID: responseID, FirstSeenAt: base.Add(time.Millisecond), Family: "indication",
			RadiusType: "access-accept", Direction: "response", Status: "paired",
			RequestID: &requestID, Decision: "info_only",
		},
	})
	if len(events) != 1 {
		t.Fatalf("events=%d, want one paired step: %+v", len(events), events)
	}
	if events[0].Summary != "number -> Access-Accept" || events[0].Phase != "indication" {
		t.Fatalf("paired summary unexpected: %+v", events[0])
	}
}

func TestDisplayRadiusTypeMapsEltexAccessResponseToAccept(t *testing.T) {
	if got := displayRadiusType("access-response"); got != "Access-Accept" {
		t.Fatalf("access-response display = %q", got)
	}
}

func mustParseUUID(value string) uuid.UUID {
	id, err := uuid.Parse(value)
	if err != nil {
		panic(err)
	}
	return id
}

func TestCallDetailByteBoundPreservesFullAggregateOutcome(t *testing.T) {
	detail := AntifraudCallDetail{
		AntifraudCallRow: AntifraudCallRow{Status: "blocked", PacketCount: 12_345},
	}
	for index := 0; index < maxCallDetailPackets; index++ {
		attributes := make([]OrderedAttribute, 10)
		for attributeIndex := range attributes {
			attributes[attributeIndex] = OrderedAttribute{
				Name: "evidence", Value: strings.Repeat("x", maxCallAttributeBytes),
			}
		}
		detail.Packets = append(detail.Packets, AntifraudPacket{
			Attributes: attributes,
		})
	}
	boundCallDetail(&detail)
	if !detail.Truncated || len(detail.Warnings) == 0 {
		t.Fatal("oversized card did not report deterministic truncation")
	}
	if detail.PacketCount != 12_345 || detail.Status != "blocked" {
		t.Fatalf("full aggregate outcome changed: count=%d status=%q",
			detail.PacketCount, detail.Status)
	}
	if size := jsonSize(detail); size > maxCallCardJSONBytes+1024 {
		t.Fatalf("bounded detail size = %d", size)
	}
}
