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

func TestEligiblePhone(t *testing.T) {
	cases := map[string]bool{
		"4996660000": true,  // 74…
		"3832888803": true,  // 73…
		"8125551212": true,  // 78…
		"9031234567": true,  // 79…
		"1234567890": false, // 71… after strip
		"5123456789": false, // 75…
		"499666000":  false, // wrong length
		"":           false,
	}
	for phone, want := range cases {
		if got := EligiblePhone(phone); got != want {
			t.Fatalf("EligiblePhone(%q)=%v want %v", phone, got, want)
		}
	}
	if !EligiblePhone(NormalizePhone("74996660000")) {
		t.Fatal("7499… should be eligible after normalize")
	}
	if EligiblePhone(NormalizePhone("71234567890")) {
		t.Fatal("7123… should not be eligible")
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
	second, err := client.Lookup(context.Background(), "4996660000")
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
	_, err = client.Lookup(context.Background(), "4996660000")
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

func TestLookupRequiresOperatorAndGarTerritory(t *testing.T) {
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
	_, err := client.Lookup(context.Background(), "4996660000")
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("want incomplete error, got %v", err)
	}
	client.mu.Lock()
	_, cached := client.cache["4996660000"]
	client.mu.Unlock()
	if cached {
		t.Fatal("incomplete result must not be cached")
	}
}

func TestLookupNotFoundIsErrorForEligible(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"found": false})
	}))
	defer server.Close()
	client := New(server.URL, "token", true)
	client.HTTPClient = server.Client()
	_, err := client.Lookup(context.Background(), "9031234567")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want not found error, got %v", err)
	}
}

func TestLookupDisabledWithoutToken(t *testing.T) {
	client := New(DefaultURL, "", true)
	result, err := client.Lookup(context.Background(), "4996660000")
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
	if SideNeedsEnrichment("71234567890", "", "") {
		t.Fatal("non-eligible must not need enrichment")
	}
}
