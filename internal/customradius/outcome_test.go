package customradius

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFinalDecisionNotApplicableWithoutCheckCall(t *testing.T) {
	device := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	base := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	reqID := uuid.New()
	respID := uuid.New()
	packets := []Packet{
		{
			ID: reqID, IsAntifraud: true, Family: FamilyIndication, RadiusType: "access-request",
			Direction: DirectionRequest, Status: PacketPaired, Decision: DecisionInfoOnly,
			ResponseID: &respID, FirstSeenAt: base, LastSeenAt: base,
			CallKey: CallKey{AcctSessionID: "s1", H323ConfID: "h1", Calling: "A", Called: "B"},
			Attributes: []Attribute{{Name: "xpgk-request-type", Value: "save_call", EventID: reqID}},
			Provenance: []EventProvenance{{EventID: reqID, DeviceID: device, ReceivedAt: base}},
		},
		{
			ID: respID, IsAntifraud: true, Family: FamilyIndication, RadiusType: "access-accept",
			Direction: DirectionResponse, Status: PacketPaired, Decision: DecisionInfoOnly,
			RequestID: &reqID, FirstSeenAt: base.Add(time.Millisecond), LastSeenAt: base.Add(time.Millisecond),
			CallKey: CallKey{AcctSessionID: "s1", H323ConfID: "h1"},
			Provenance: []EventProvenance{{EventID: respID, DeviceID: device, ReceivedAt: base}},
		},
		{
			ID: uuid.New(), IsAntifraud: true, Family: FamilyAccounting, RadiusType: "accounting-request",
			Direction: DirectionRequest, Status: PacketPaired, Phase: PhaseEnd, Decision: DecisionAcknowledgement,
			FirstSeenAt: base.Add(time.Second), LastSeenAt: base.Add(time.Second),
			CallKey: CallKey{AcctSessionID: "s1", H323ConfID: "h1"},
			Attributes: []Attribute{
				{Name: "acct-session-time", Value: "15", EventID: uuid.Nil},
				{Name: "h323-disconnect-cause", Value: "0x10", EventID: uuid.Nil},
			},
			Provenance: []EventProvenance{{DeviceID: device, ReceivedAt: base}},
		},
	}
	call := buildCall("h323:h1", []int{0, 1, 2}, packets)
	if call.FinalDecision != "not_applicable" {
		t.Fatalf("finalDecision=%q, want not_applicable", call.FinalDecision)
	}
	if call.VerificationResult != "absent" || !call.IndicationAcked {
		t.Fatalf("outcome flags unexpected: %+v", call)
	}
	if call.Accounting.SessionDuration == nil || *call.Accounting.SessionDuration != 15 {
		t.Fatalf("session duration=%v", call.Accounting.SessionDuration)
	}
	if call.Accounting.DisconnectCauseQ850 == nil || *call.Accounting.DisconnectCauseQ850 != 16 {
		t.Fatalf("q850=%v", call.Accounting.DisconnectCauseQ850)
	}
	if call.Status != CallCompleted {
		t.Fatalf("status=%q, want completed", call.Status)
	}
}

func TestFinalDecisionBlockedOnCheckCallReject(t *testing.T) {
	device := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	base := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	reqID := uuid.New()
	respID := uuid.New()
	packets := []Packet{
		{
			ID: reqID, IsAntifraud: true, Family: FamilyVerification, RadiusType: "access-request",
			Direction: DirectionRequest, Status: PacketPaired, ResponseID: &respID,
			FirstSeenAt: base, LastSeenAt: base,
			CallKey: CallKey{AcctSessionID: "s1", H323ConfID: "h1"},
			Attributes: []Attribute{{Name: "xpgk-request-type", Value: "check_call", EventID: reqID}},
			Provenance: []EventProvenance{{EventID: reqID, DeviceID: device, ReceivedAt: base}},
		},
		{
			ID: respID, IsAntifraud: true, Family: FamilyVerification, RadiusType: "access-reject",
			Direction: DirectionResponse, Status: PacketPaired, Decision: DecisionDeny, RequestID: &reqID,
			FirstSeenAt: base.Add(time.Millisecond), LastSeenAt: base.Add(time.Millisecond),
			CallKey: CallKey{AcctSessionID: "s1", H323ConfID: "h1"},
			Provenance: []EventProvenance{{EventID: respID, DeviceID: device, ReceivedAt: base}},
		},
	}
	call := buildCall("h323:h1", []int{0, 1}, packets)
	if call.FinalDecision != "blocked" || call.VerificationResult != "reject" {
		t.Fatalf("decision=%q result=%q", call.FinalDecision, call.VerificationResult)
	}
}
