package voipmonitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNormalizeCallID(t *testing.T) {
	if got := NormalizeCallID(" AbC@host.example "); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeCallID("sip-abc"); got != "sip-abc" {
		t.Fatalf("got %q", got)
	}
}

func TestMatchExactSIPCallID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"cdrId": "42", "callId": "sip-abc@vm", "caller": "79001112233", "called": "79005556677",
			"calldate": "2026-07-27 12:00:00", "duration": 12, "connect_duration": 10,
		}})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, User: "u", Password: "p", HTTPClient: server.Client()},
		GUIBase: server.URL, CallIDWindow: 30 * time.Minute, MinScore: 60,
		Now: func() time.Time { return time.Date(2026, 7, 27, 12, 0, 1, 0, time.UTC) },
	}
	setup := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	result, err := matcher.Match(context.Background(), CDRCandidate{
		DeviceID: uuid.New(), SourceSystem: SourceEltex, SourceRecordID: uuid.New(),
		SetupTime: setup, Caller: "79001112233", Called: "79005556677",
		SIPCallIDs: []string{"sip-abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusMatchedExact || result.Score != 100 {
		t.Fatalf("result=%+v", result)
	}
	if result.VM == nil || result.VM.CDRID != "42" || result.CardURL == "" {
		t.Fatalf("vm/card missing: %+v", result)
	}
	if !AuditExactCallIDInvariant(CDRCandidate{SIPCallIDs: []string{"sip-abc"}}, result) {
		t.Fatal("exact invariant failed")
	}
}

func TestMatchMultiLegSameCallIDIsExact(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{
				"cdrId": "10", "callId": "shared-id", "caller": "100", "called": "200",
				"calldate": "2026-07-27 12:00:00", "duration": 10,
				"sipcallerip": "1.1.1.1", "sipcalledip": "2.2.2.2",
			},
			{
				"cdrId": "11", "callId": "shared-id", "caller": "100", "called": "200",
				"calldate": "2026-07-27 12:00:01", "duration": 10,
				"sipcallerip": "9.9.9.9", "sipcalledip": "8.8.8.8",
			},
		})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		GUIBase: "https://vm.example", CallIDWindow: 30 * time.Minute,
	}
	dur := int64(10)
	result, err := matcher.Match(context.Background(), CDRCandidate{
		SourceSystem: SourceEltex,
		SetupTime:    time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		Caller:       "100", Called: "200", DurationSec: &dur,
		CallerIP: "1.1.1.1", CalledIP: "2.2.2.2",
		SIPCallIDs: []string{"shared-id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusMatchedExact {
		t.Fatalf("status=%q want matched_exact", result.Status)
	}
	if result.VM == nil || result.VM.CDRID != "10" {
		t.Fatalf("expected leg cdrId=10, got %+v", result.VM)
	}
}

func TestMatchFallbackAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"cdrId": "1", "callId": "a", "caller": "79001112233", "called": "79005556677",
				"calldate": "2026-07-27 12:00:00", "duration": 10},
			{"cdrId": "2", "callId": "b", "caller": "79001112233", "called": "79005556677",
				"calldate": "2026-07-27 12:00:01", "duration": 10},
		})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		CallIDWindow: 30 * time.Minute, FallbackWindow: 2 * time.Minute,
		MinScore: 60, DisambiguityMargin: 8,
	}
	dur := int64(10)
	result, err := matcher.Match(context.Background(), CDRCandidate{
		SourceSystem: SourceEltex, SetupTime: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		Caller: "79001112233", Called: "79005556677", DurationSec: &dur,
		CallerNumbers: []string{"79001112233"}, CalledNumbers: []string{"79005556677"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusAmbiguous {
		t.Fatalf("status=%q", result.Status)
	}
	if result.MissReason != MissFallbackAmbiguous {
		t.Fatalf("miss_reason=%q", result.MissReason)
	}
	if result.CardURL != "" {
		t.Fatal("ambiguous must not have URL")
	}
}

func TestMatchFallbackB2BUA(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"cdrId": "77", "callId": "vm-regenerated", "caller": "79001112233", "called": "79005556677",
			"calldate": "2026-07-27 12:00:02", "duration": 30,
			"sipcallerip": "10.0.0.1", "sipcalledip": "10.0.0.2",
		}})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		GUIBase: "https://vm.example",
		CallIDWindow: 30 * time.Minute, FallbackWindow: 2 * time.Minute,
		MinScore: 60, DisambiguityMargin: 8,
	}
	dur := int64(30)
	result, err := matcher.Match(context.Background(), CDRCandidate{
		SourceSystem: SourceEltex,
		SetupTime:    time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		Caller:       "79001112233", Called: "79005556677",
		CallerNumbers: []string{"79001112233"}, CalledNumbers: []string{"79005556677"},
		CallerIP: "10.0.0.1", CalledIP: "10.0.0.2",
		DurationSec: &dur,
		SIPCallIDs:  []string{"smg-only-call-id"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusMatchedFallback {
		t.Fatalf("status=%q result=%+v", result.Status, result)
	}
	if result.VM == nil || result.VM.CDRID != "77" {
		t.Fatalf("vm=%+v", result.VM)
	}
}

func TestMatchDifferentCallIDsNotExact(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"cdrId": "9", "callId": "other-id", "caller": "100", "called": "200",
			"calldate": "2026-07-27 12:00:00", "duration": 5,
		}})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		CallIDWindow: 30 * time.Minute, FallbackWindow: 2 * time.Minute, MinScore: 60,
	}
	result, err := matcher.Match(context.Background(), CDRCandidate{
		SourceSystem: SourceEltex,
		SetupTime:    time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		SIPCallIDs:   []string{"my-id"},
		// Weak numbers on purpose — must not invent exact link.
		Caller: "999", Called: "888",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == StatusMatchedExact {
		t.Fatalf("must not match exact: %+v", result)
	}
}

func TestUniqueCDRIDAssignment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"cdrId": "1", "callId": "shared", "caller": "100", "called": "200",
			"calldate": "2026-07-27 12:00:00", "duration": 10,
		}})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		GUIBase: "https://vm.example", CallIDWindow: 30 * time.Minute,
	}
	setup := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	cands := []CDRCandidate{
		{SourceSystem: SourceEltex, SourceRecordID: uuid.New(), SetupTime: setup, SIPCallIDs: []string{"shared"}},
		{SourceSystem: SourceEltex, SourceRecordID: uuid.New(), SetupTime: setup, SIPCallIDs: []string{"shared"}},
	}
	results, err := matcher.MatchBucket(context.Background(), cands)
	if err != nil {
		t.Fatal(err)
	}
	if issues := AuditLinkInvariants(cands, results); len(issues) > 0 {
		t.Fatalf("invariants: %v", issues)
	}
	matched := 0
	for _, r := range results {
		if r.Status == StatusMatchedExact {
			matched++
		}
	}
	if matched != 1 {
		t.Fatalf("expected exactly one exact match, got %d (%+v)", matched, results)
	}
}

func TestBuildCardURL(t *testing.T) {
	got := BuildCardURL("", "https://vm.example", CardURLParts{CallID: `a"b`, CDRID: "9"})
	want := "https://vm.example/admin.php?cdr_filter=" + url.QueryEscape("{fId:9}")
	if got != want {
		t.Fatalf("url=%s want=%s", got, want)
	}
	got = BuildCardURL("", "https://vm.example", CardURLParts{CallID: `abc`})
	want = "https://vm.example/admin.php?cdr_filter=" + url.QueryEscape(`{fcallid:"abc"}`)
	if got != want {
		t.Fatalf("callid url=%s want=%s", got, want)
	}
	got = BuildCardURL(
		`'{gui_base}/admin.php?cdr_filter={fcallid:"{voipmonitor_call_id}"}'`,
		"https://vm.example", CardURLParts{CDRID: "42", CallID: "x"},
	)
	want = "https://vm.example/admin.php?cdr_filter=" + url.QueryEscape("{fId:42}")
	if got != want {
		t.Fatalf("quoted template url=%s want=%s", got, want)
	}
}
