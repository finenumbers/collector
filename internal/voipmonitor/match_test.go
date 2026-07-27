package voipmonitor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMatchExactSIPCallID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"cdrId": "42", "callId": "sip-abc", "caller": "79001112233", "called": "79005556677",
			"calldate": "2026-07-27 12:00:00", "duration": 12, "connect_duration": 10,
		}})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, User: "u", Password: "p", HTTPClient: server.Client()},
		GUIBase: server.URL, TimeSkew: 5 * time.Second, MinScore: 60,
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
	if result.Status != StatusMatchedExact || result.Method != "sip_call_id_in" || result.Score != 100 {
		t.Fatalf("result=%+v", result)
	}
	if result.VM == nil || result.VM.CDRID != "42" || result.CardURL == "" {
		t.Fatalf("vm/card missing: %+v", result)
	}
}

func TestMatchFallbackAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"cdrId": "1", "callId": "a", "caller": "100", "called": "200",
				"calldate": "2026-07-27 12:00:00", "duration": 10},
			{"cdrId": "2", "callId": "b", "caller": "100", "called": "200",
				"calldate": "2026-07-27 12:00:01", "duration": 10},
		})
	}))
	defer server.Close()
	matcher := &Matcher{
		Client: &Client{BaseURL: server.URL, HTTPClient: server.Client()},
		TimeSkew: 5 * time.Second, MinScore: 60,
	}
	dur := int64(10)
	result, err := matcher.Match(context.Background(), CDRCandidate{
		SourceSystem: SourceEltex, SetupTime: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		Caller: "100", Called: "200", DurationSec: &dur,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusAmbiguous {
		t.Fatalf("status=%q", result.Status)
	}
}

func TestBuildCardURL(t *testing.T) {
	got := BuildCardURL("", "https://vm.example", CardURLParts{CallID: `a"b`, CDRID: "9"})
	if !containsAll(got, "https://vm.example/admin.php", "fcallid") {
		t.Fatalf("url=%s", got)
	}
}

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !contains(value, part) {
			return false
		}
	}
	return true
}

func contains(value, part string) bool {
	return len(part) == 0 || (len(value) >= len(part) && (value == part || len(value) > 0 &&
		(func() bool {
			for i := 0; i+len(part) <= len(value); i++ {
				if value[i:i+len(part)] == part {
					return true
				}
			}
			return false
		})()))
}
