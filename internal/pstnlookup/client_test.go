package pstnlookup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"collector/internal/lookuptelemetry"
)

func TestNormalizePhone(t *testing.T) {
	cases := map[string]string{
		"4996660000":        "4996660000",
		"+7 (499) 666-0000": "4996660000",
		"84996660000":       "4996660000",
		"74996660000":       "4996660000",
		"":                  "",
		"abc":               "",
	}
	for raw, want := range cases {
		if got := NormalizePhone(raw); got != want {
			t.Fatalf("NormalizePhone(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestEligiblePhoneRequires11Digit73_74_78_79(t *testing.T) {
	cases := map[string]bool{
		"74996660000":      true, // 74…
		"84996660000":      true, // trunk 8 → 74…
		"73832888803":      true, // 73…
		"78125551212":      true, // 78…
		"79031234567":      true, // 79…
		"+7 903 123-45-67": true,
		"78007777373":      true, // 8-800 with country 7
		"88002050555":      true, // 8-800 trunk 8
		"4996660000":       false, // bare 10-digit national — never
		"8800205055":       false, // 10-digit 8800…
		"4712780077":       false, // 10-digit 47…
		"8432700050":       false, // 10-digit
		"71234567890":      false, // 11-digit 71…
		"75031234567":      false, // 11-digit 75…
		"88125551212":      true,  // trunk 8 of 7812…

		"": false,
	}
	for phone, want := range cases {
		if got := EligiblePhone(phone); got != want {
			t.Fatalf("EligiblePhone(%q)=%v want %v", phone, got, want)
		}
	}
}

func TestLookupSkipsBare10DigitNationals(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"found":false,"phone":"8800205055"}`))
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	for _, phone := range []string{"8800205055", "4712780077", "8432700050", "4996660000"} {
		result, err := client.Lookup(context.Background(), phone)
		if err != nil || result != (Result{}) {
			t.Fatalf("non-eligible %q = %#v err=%v", phone, result, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("API hits=%d want 0 for bare 10-digit numbers", hits.Load())
	}
}

func TestLookupCachesForTTL(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"found": true,
			"phone": r.URL.Query().Get("phone"),
			"data": map[string]any{
				"operator":     `ООО "ФРОНТИР НЕТВОРК"`,
				"region":       "г. Москва",
				"garTerritory": "город Москва",
			},
		})
	}))
	defer server.Close()

	client := New(server.URL, "test-token", true)
	client.HTTPClient = server.Client()
	client.CacheTTL = time.Hour

	first, err := client.Lookup(context.Background(), "84996660000")
	if err != nil {
		t.Fatal(err)
	}
	if first.Operator == "" || first.Region != "город Москва" {
		t.Fatalf("unexpected result %#v", first)
	}
	second, err := client.Lookup(context.Background(), "74996660000")
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("cache miss: %#v vs %#v", first, second)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits=%d want 1", hits.Load())
	}

	client.mu.Lock()
	client.cache["4996660000"] = cacheEntry{result: first, expiresAt: time.Now().Add(-time.Second)}
	client.mu.Unlock()
	_, err = client.Lookup(context.Background(), "74996660000")
	if err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatalf("expired cache hits=%d want 2", hits.Load())
	}
}

func TestLookupSkipsNonEligible(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	result, err := client.Lookup(context.Background(), "71234567890")
	if err != nil || result != (Result{}) {
		t.Fatalf("non-eligible = %#v err=%v", result, err)
	}
	if hits.Load() != 0 {
		t.Fatalf("hits=%d want 0", hits.Load())
	}
}

func TestLookupIncompleteBecomesNotFoundSentinel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"found": true,
			"data": map[string]any{
				"operator":     "Op",
				"region":       "old-region",
				"garTerritory": "",
			},
		})
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	client.Telemetry = &lookuptelemetry.Registry{}
	result, err := client.Lookup(context.Background(), "74996660000")
	if err != nil {
		t.Fatal(err)
	}
	if result.Operator != ValueNotFound || result.Region != ValueNotFound {
		t.Fatalf("want not-found sentinel, got %#v", result)
	}
	snap := client.Telemetry.Snapshot()["pstn"]
	if snap.Errors != 0 {
		t.Fatalf("incomplete must not count as error, errors=%d", snap.Errors)
	}
}

func TestLookupNotFoundReturnsSentinelWithoutError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"found": false, "phone": r.URL.Query().Get("phone")})
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	client.Telemetry = &lookuptelemetry.Registry{}
	result, err := client.Lookup(context.Background(), "79031234567")
	if err != nil {
		t.Fatal(err)
	}
	if result.Operator != ValueNotFound || result.Region != ValueNotFound {
		t.Fatalf("want sentinel, got %#v", result)
	}
	if snap := client.Telemetry.Snapshot()["pstn"]; snap.Errors != 0 || snap.Lookups != 1 {
		t.Fatalf("telemetry=%+v want lookups=1 errors=0", snap)
	}
	if SideNeedsEnrichment("79031234567", result.Operator, result.Region) {
		t.Fatal("sentinel must resolve enrichment")
	}
}

func TestLookupHTTP404ReturnsSentinel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"found":false,"phone":"8432700050"}`))
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	client.Telemetry = &lookuptelemetry.Registry{}
	result, err := client.Lookup(context.Background(), "78432700050")
	if err != nil {
		t.Fatal(err)
	}
	if result != notFoundResult() {
		t.Fatalf("got %#v", result)
	}
	if snap := client.Telemetry.Snapshot()["pstn"]; snap.Errors != 0 {
		t.Fatalf("404 must not be RecordError, errors=%d last=%q", snap.Errors, snap.LastError)
	}
}

func TestLookupDisabledWithoutToken(t *testing.T) {
	client := New(DefaultURL, "", true)
	result, err := client.Lookup(context.Background(), "74996660000")
	if err != nil || result != (Result{}) {
		t.Fatalf("disabled lookup = %#v err=%v", result, err)
	}
}

func TestSideNeedsEnrichment(t *testing.T) {
	if !SideNeedsEnrichment("79031234567", "", "") {
		t.Fatal("empty operator/region must need enrichment")
	}
	if !SideNeedsEnrichment("79031234567", "Op", "") {
		t.Fatal("missing garTerritory must need enrichment")
	}
	if SideNeedsEnrichment("79031234567", "Op", "Gar") {
		t.Fatal("complete side must not need enrichment")
	}
	if SideNeedsEnrichment("79031234567", ValueNotFound, ValueNotFound) {
		t.Fatal("not-found sentinel must not need enrichment")
	}
	if SideNeedsEnrichment("71234567890", "", "") {
		t.Fatal("non-eligible must not need enrichment")
	}
	if SideNeedsEnrichment("8800205055", "", "") {
		t.Fatal("bare 10-digit must not need enrichment")
	}
}

func TestMarkIneligible(t *testing.T) {
	op, reg, ok := MarkIneligible("8432700050", "", "", false)
	if !ok || op != ValueIneligible || reg != ValueIneligible {
		t.Fatalf("got %q %q ok=%v", op, reg, ok)
	}
	if _, _, ok := MarkIneligible("79031234567", "", "", false); ok {
		t.Fatal("eligible must not be marked ineligible")
	}
	if _, _, ok := MarkIneligible("8432700050", "Op", "Reg", false); ok {
		t.Fatal("already resolved must not overwrite without force")
	}
	op, reg, ok = MarkIneligible("8432700050", "Op", "Reg", true)
	if !ok || op != ValueIneligible {
		t.Fatalf("force got %q %q ok=%v", op, reg, ok)
	}
}

func TestLookupManyKeepsNotFoundSentinel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"found": false})
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	out := client.LookupMany(context.Background(), []string{"79031234567", "8432700050"}, 2)
	if got := out[NormalizePhone("79031234567")]; got != notFoundResult() {
		t.Fatalf("eligible not-found missing from map: %#v", out)
	}
	if _, ok := out[NormalizePhone("8432700050")]; ok {
		t.Fatal("bare 10-digit must not appear in lookup map")
	}
}

func TestLookupServerErrorStillErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`oops`))
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	client.Telemetry = &lookuptelemetry.Registry{}
	_, err := client.Lookup(context.Background(), "79031234567")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("want 502 error, got %v", err)
	}
	if snap := client.Telemetry.Snapshot()["pstn"]; snap.Errors != 1 {
		t.Fatalf("telemetry errors=%d want 1", snap.Errors)
	}
}
