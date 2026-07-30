package pstnlookup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func TestLookupCachesForTTL(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"found": true,
			"phone": r.URL.Query().Get("phone"),
			"data": map[string]any{
				"operator": `ООО "ФРОНТИР НЕТВОРК"`,
				"region":   "г. Москва",
			},
		})
	}))
	defer server.Close()

	client := New(server.URL, "test-token")
	client.HTTPClient = server.Client()
	client.CacheTTL = time.Hour

	first, err := client.Lookup(context.Background(), "84996660000")
	if err != nil {
		t.Fatal(err)
	}
	if first.Operator == "" || first.Region == "" {
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

func TestLookupDisabledWithoutToken(t *testing.T) {
	client := New(DefaultURL, "")
	result, err := client.Lookup(context.Background(), "4996660000")
	if err != nil || result != (Result{}) {
		t.Fatalf("disabled lookup = %#v err=%v", result, err)
	}
}
