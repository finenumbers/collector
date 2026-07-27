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

func TestCompactSessionMatchesSpacedEltexID(t *testing.T) {
	device, now := uuid.New(), time.Now().UTC()
	spaced := "11000307 6a62aaa9 c9f5297a 4f6a3001"
	compact := "110003076a62aaa9c9f5297a4f6a3001"
	result := Reconcile(Config{}, now, []CDR{{
		ID: uuid.New(), DeviceID: device, EventTime: now, IngestedAt: now,
		AcctSessionID: compact, Calling: "79251100001", Called: "79251100002",
		Enabled: true, PolicyRevision: 1,
	}}, []Call{{
		ID: uuid.New(), DeviceID: device, EventTime: now, AcctSessionID: spaced,
		Calling: "79251100001", Called: "79251100002", PolicyRevision: 1,
	}})
	if len(result.Assignments) != 1 || result.Assignments[0].Method != "acct_session_id" {
		t.Fatalf("compact/spaced session did not match: %+v", result.Assignments)
	}
	if result.Calls[0].State != StateMatched {
		t.Fatalf("AF coverage=%q, want matched", result.Calls[0].State)
	}
}

func TestSecondaryNumberMismatchRejectsPrimaryHit(t *testing.T) {
	device, now := uuid.New(), time.Now().UTC()
	result := Reconcile(Config{}, now, []CDR{{
		ID: uuid.New(), DeviceID: device, EventTime: now, IngestedAt: now,
		AcctSessionID: "session-1", Calling: "100", Called: "200",
		Enabled: true, PolicyRevision: 1,
	}}, []Call{{
		ID: uuid.New(), DeviceID: device, EventTime: now, AcctSessionID: "session-1",
		Calling: "111", Called: "222", PolicyRevision: 1,
	}})
	if len(result.Assignments) != 0 {
		t.Fatal("number mismatch must not assign")
	}
	if result.Coverage[0].Reason != "number_mismatch" {
		t.Fatalf("reason=%q", result.Coverage[0].Reason)
	}
}

func TestSecondaryTimeMismatchRejectsPrimaryHit(t *testing.T) {
	device, now := uuid.New(), time.Now().UTC()
	result := Reconcile(Config{TimeMatchWindow: time.Hour}, now, []CDR{{
		ID: uuid.New(), DeviceID: device, EventTime: now.Add(-3 * time.Hour),
		IngestedAt: now, AcctSessionID: "session-1", Enabled: true, PolicyRevision: 1,
	}}, []Call{{
		ID: uuid.New(), DeviceID: device, EventTime: now, AcctSessionID: "session-1",
		PolicyRevision: 1,
	}})
	if len(result.Assignments) != 0 || result.Coverage[0].Reason != "time_mismatch" {
		t.Fatalf("time mismatch not enforced: %+v", result)
	}
}

func TestCallCoverageAgesWithoutCDR(t *testing.T) {
	device := uuid.New()
	event := time.Now().UTC().Add(-20 * time.Minute)
	result := Reconcile(Config{
		ExpectedGrace: 5 * time.Minute, LateThreshold: 10 * time.Minute,
		MissingTerminal: 30 * time.Minute,
	}, time.Now().UTC(), nil, []Call{{
		ID: uuid.New(), DeviceID: device, EventTime: event, AcctSessionID: "orphan",
		PolicyRevision: 1,
	}})
	if result.Calls[0].State != StateLate {
		t.Fatalf("AF coverage=%q, want late", result.Calls[0].State)
	}
}
