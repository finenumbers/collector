package reconciliation

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStrictSessionAndOneToOne(t *testing.T) {
	device, now := uuid.New(), time.Now().UTC()
	calls := []Call{
		{ID: uuid.New(), DeviceID: device, EventTime: now, AcctSessionID: " Session-A ", PolicyRevision: 1},
		{ID: uuid.New(), DeviceID: device, EventTime: now, AcctSessionID: "session-b", PolicyRevision: 1},
	}
	cdrs := []CDR{
		{ID: uuid.New(), DeviceID: device, EventTime: now, IngestedAt: now,
			AcctSessionID: "session-a", Calling: "100", Called: "200", Enabled: true, PolicyRevision: 1},
		{ID: uuid.New(), DeviceID: device, EventTime: now, IngestedAt: now,
			AcctSessionID: "session-a", Calling: "100", Called: "200", Enabled: true, PolicyRevision: 1},
	}
	result := Reconcile(Config{}, now, cdrs, calls)
	if len(result.Assignments) != 1 {
		t.Fatalf("assignments=%d, want one-to-one match", len(result.Assignments))
	}
	if result.Assignments[0].Method != "acct_session_id" {
		t.Fatalf("method=%q", result.Assignments[0].Method)
	}
	ambiguous := 0
	for _, coverage := range result.Coverage {
		if coverage.Ambiguous && coverage.AmbiguityReason == "call_already_assigned" {
			ambiguous++
		}
	}
	if ambiguous != 1 {
		t.Fatalf("one-to-one collision ambiguity=%d, want 1", ambiguous)
	}
}

func TestH323RequiresRealFieldAndUniqueCandidate(t *testing.T) {
	device, now := uuid.New(), time.Now().UTC()
	calls := []Call{
		{ID: uuid.New(), DeviceID: device, EventTime: now, H323ConfID: "conf-1", Calling: "100", PolicyRevision: 1},
		{ID: uuid.New(), DeviceID: device, EventTime: now, H323ConfID: "conf-1", Calling: "100", PolicyRevision: 1},
	}
	withoutField := Reconcile(Config{}, now, []CDR{{
		ID: uuid.New(), DeviceID: device, EventTime: now, IngestedAt: now,
		Calling: "100", Enabled: true, PolicyRevision: 1,
	}}, calls)
	if len(withoutField.Assignments) != 0 {
		t.Fatal("numbers selected a call")
	}
	ambiguous := Reconcile(Config{}, now, []CDR{{
		ID: uuid.New(), DeviceID: device, EventTime: now, IngestedAt: now,
		H323FieldValues: []string{"conf-1"}, Enabled: true, PolicyRevision: 1,
	}}, calls)
	if !ambiguous.Coverage[0].Ambiguous || len(ambiguous.Assignments) != 0 {
		t.Fatal("duplicate H323 candidates must remain ambiguous")
	}
}

func TestLateEvidenceAndStateAging(t *testing.T) {
	device := uuid.New()
	eventTime := time.Now().UTC().Add(-time.Hour)
	call := Call{
		ID: uuid.New(), DeviceID: device, EventTime: eventTime, AcctSessionID: "late",
		PolicyRevision: 1,
	}
	cdr := CDR{
		ID: uuid.New(), DeviceID: device, EventTime: eventTime,
		IngestedAt: eventTime.Add(40 * time.Minute), AcctSessionID: "late",
		Enabled: true, PolicyRevision: 1,
	}
	result := Reconcile(Config{LateThreshold: 5 * time.Minute}, time.Now().UTC(), []CDR{cdr}, []Call{call})
	if result.Coverage[0].State != StateLate {
		t.Fatalf("state=%q, want late", result.Coverage[0].State)
	}
	missing := Reconcile(Config{MissingTerminal: 30 * time.Minute}, time.Now().UTC(), []CDR{{
		ID: uuid.New(), DeviceID: device, EventTime: eventTime, IngestedAt: eventTime, Enabled: true,
	}}, nil)
	if missing.Coverage[0].State != StateMissing {
		t.Fatalf("state=%q, want missing", missing.Coverage[0].State)
	}
}

func TestPolicyRevisionMismatchNeverMatches(t *testing.T) {
	device, now := uuid.New(), time.Now().UTC()
	result := Reconcile(Config{}, now, []CDR{{
		ID: uuid.New(), DeviceID: device, EventTime: now, IngestedAt: now,
		AcctSessionID: "same", Enabled: true, PolicyRevision: 2,
	}}, []Call{{
		ID: uuid.New(), DeviceID: device, EventTime: now,
		AcctSessionID: "same", PolicyRevision: 1,
	}})
	if len(result.Assignments) != 0 {
		t.Fatal("different policy revisions matched")
	}
	if result.NextDeadline == nil ||
		!result.NextDeadline.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("missing-state aging deadline=%v", result.NextDeadline)
	}
}
