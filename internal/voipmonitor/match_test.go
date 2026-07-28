package voipmonitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type mockVMCall struct {
	CDRID    string
	CallID   string
	Caller   string
	Called   string
	Calldate string
	Duration int
	CallerIP string
	CalledIP string
}

func newVMServer(t *testing.T, catalog []mockVMCall) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		task := r.Form.Get("task")
		var params map[string]any
		_ = json.Unmarshal([]byte(r.Form.Get("params")), &params)
		switch task {
		case "getShareURL":
			cdrID, _ := params["cdrId"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"url": "https://vm.example/share/" + cdrID,
			})
			return
		case "getVoipCalls":
			wantCallID, _ := params["callId"].(string)
			wantCDRID := ""
			switch typed := params["cdrId"].(type) {
			case string:
				wantCDRID = typed
			case float64:
				wantCDRID = strconv.FormatInt(int64(typed), 10)
			}
			caller, _ := params["caller"].(string)
			called, _ := params["called"].(string)
			out := make([]map[string]any, 0)
			for _, item := range catalog {
				if wantCDRID != "" && item.CDRID != wantCDRID {
					continue
				}
				if wantCallID != "" && !callIDsEqual(wantCallID, item.CallID) {
					continue
				}
				if wantCallID == "" && wantCDRID == "" {
					if caller != "" && !strings.HasSuffix(digits(item.Caller), digits(caller)) &&
						!strings.Contains(digits(item.Caller), digits(caller)) {
						continue
					}
					if called != "" && !strings.HasSuffix(digits(item.Called), digits(called)) &&
						!strings.Contains(digits(item.Called), digits(called)) {
						continue
					}
				}
				row := map[string]any{
					"cdrId": item.CDRID, "callId": item.CallID,
					"caller": item.Caller, "called": item.Called,
					"calldate": item.Calldate, "duration": item.Duration,
				}
				if item.CallerIP != "" {
					row["sipcallerip"] = item.CallerIP
				}
				if item.CalledIP != "" {
					row["sipcalledip"] = item.CalledIP
				}
				out = append(out, row)
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		default:
			http.Error(w, "unknown task", http.StatusBadRequest)
		}
	}))
}

func TestNormalizeAndQueryVariants(t *testing.T) {
	if got := NormalizeCallID(" AbC@host.example "); got != "abc" {
		t.Fatalf("got %q", got)
	}
	variants := CallIDQueryVariants("Sip-ABC@host")
	if len(variants) < 2 {
		t.Fatalf("variants=%v", variants)
	}
	if variants[0] != "Sip-ABC@host" {
		t.Fatalf("raw first got %q", variants[0])
	}
}

func TestMatchExactSIPCallID(t *testing.T) {
	server := newVMServer(t, []mockVMCall{{
		CDRID: "42", CallID: "sip-abc@vm", Caller: "79001112233", Called: "79005556677",
		Calldate: "2026-07-27 12:00:00", Duration: 12,
	}})
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
	if strings.Contains(result.CardURL, "fId") {
		t.Fatalf("must not use fId: %s", result.CardURL)
	}
	if !strings.Contains(result.CardURL, "fcallid") {
		t.Fatalf("expected fcallid url: %s", result.CardURL)
	}
	if !AuditExactCallIDInvariant(CDRCandidate{SIPCallIDs: []string{"sip-abc"}}, result) {
		t.Fatal("exact invariant failed")
	}
}

func TestMatchMultiLegSameCallIDIsExact(t *testing.T) {
	server := newVMServer(t, []mockVMCall{
		{
			CDRID: "10", CallID: "shared-id", Caller: "100", Called: "200",
			Calldate: "2026-07-27 12:00:00", Duration: 10,
			CallerIP: "1.1.1.1", CalledIP: "2.2.2.2",
		},
		{
			CDRID: "11", CallID: "shared-id", Caller: "100", Called: "200",
			Calldate: "2026-07-27 12:00:01", Duration: 10,
			CallerIP: "9.9.9.9", CalledIP: "8.8.8.8",
		},
	})
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
	server := newVMServer(t, []mockVMCall{
		{CDRID: "1", CallID: "a", Caller: "79001112233", Called: "79005556677",
			Calldate: "2026-07-27 12:00:00", Duration: 10},
		{CDRID: "2", CallID: "b", Caller: "79001112233", Called: "79005556677",
			Calldate: "2026-07-27 12:00:01", Duration: 10},
	})
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
	server := newVMServer(t, []mockVMCall{{
		CDRID: "77", CallID: "vm-regenerated", Caller: "79001112233", Called: "79005556677",
		Calldate: "2026-07-27 12:00:02", Duration: 30,
		CallerIP: "10.0.0.1", CalledIP: "10.0.0.2",
	}})
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
	server := newVMServer(t, []mockVMCall{{
		CDRID: "9", CallID: "other-id", Caller: "100", Called: "200",
		Calldate: "2026-07-27 12:00:00", Duration: 5,
	}})
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		CallIDWindow: 30 * time.Minute, FallbackWindow: 2 * time.Minute, MinScore: 60,
	}
	result, err := matcher.Match(context.Background(), CDRCandidate{
		SourceSystem: SourceEltex,
		SetupTime:    time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		SIPCallIDs:   []string{"my-id"},
		Caller:       "999", Called: "888",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == StatusMatchedExact {
		t.Fatalf("must not match exact: %+v", result)
	}
}

func TestUniqueCDRIDAssignment(t *testing.T) {
	server := newVMServer(t, []mockVMCall{{
		CDRID: "1", CallID: "shared", Caller: "100", Called: "200",
		Calldate: "2026-07-27 12:00:00", Duration: 10,
	}})
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

func TestBuildCardURLUsesFcallidNotFId(t *testing.T) {
	got := BuildCardURL("", "https://vm.example", CardURLParts{CallID: `a"b`, CDRID: "9"})
	want := "https://vm.example/admin.php?cdr_filter=" + url.QueryEscape(`{fcallid:"a\"b"}`)
	if got != want {
		t.Fatalf("url=%s want=%s", got, want)
	}
	got = BuildCardURL("", "https://vm.example", CardURLParts{CallID: `abc`})
	want = "https://vm.example/admin.php?cdr_filter=" + url.QueryEscape(`{fcallid:"abc"}`)
	if got != want {
		t.Fatalf("callid url=%s want=%s", got, want)
	}
	got = BuildCardURL(
		`{gui_base}/admin.php?cdr_filter={fcallid:"{voipmonitor_call_id}"}`,
		"https://vm.example", CardURLParts{CDRID: "42", CallID: "x"},
	)
	if !strings.Contains(got, "fcallid") || strings.Contains(got, "fId") {
		t.Fatalf("template url=%s", got)
	}
}

func TestRewriteLegacyCardURL(t *testing.T) {
	legacy := "https://vm.example/admin.php?cdr_filter=" + url.QueryEscape("{fId:42}")
	got := RewriteLegacyCardURL(legacy, "", "sip-abc", time.Time{})
	if strings.Contains(got, "fId") || !strings.Contains(got, "fcallid") {
		t.Fatalf("got %s", got)
	}
	if !strings.Contains(got, url.QueryEscape(`{fcallid:"sip-abc"}`)) &&
		!strings.Contains(got, "sip-abc") {
		t.Fatalf("missing call id in %s", got)
	}
}

func TestShareURLPreferredWhenEnabled(t *testing.T) {
	server := newVMServer(t, []mockVMCall{{
		CDRID: "42", CallID: "sip-abc", Caller: "1", Called: "2",
		Calldate: "2026-07-27 12:00:00", Duration: 1,
	}})
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		GUIBase: "https://vm.example", CallIDWindow: 30 * time.Minute, UseShareURL: true,
	}
	result, err := matcher.Match(context.Background(), CDRCandidate{
		SourceSystem: SourceEltex,
		SetupTime:    time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		SIPCallIDs:   []string{"sip-abc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.CardURL != "https://vm.example/share/42" {
		t.Fatalf("card=%s", result.CardURL)
	}
}
