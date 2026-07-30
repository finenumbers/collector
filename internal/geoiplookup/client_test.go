package geoiplookup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStripHostPort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5060":           "1.2.3.4",
		"1.2.3.4":                "1.2.3.4",
		"[2001:db8::1]:5060":     "2001:db8::1",
		"2001:db8::1":            "2001:db8::1",
		"":                       "",
		"  10.0.0.1:1234  ":      "10.0.0.1",
	}
	for raw, want := range cases {
		if got := StripHostPort(raw); got != want {
			t.Fatalf("StripHostPort(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestLookupPOST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method %s", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["ip"] != "8.8.8.8" {
			t.Fatalf("ip=%q", body["ip"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"city": map[string]any{"countryIsoCode": "US", "cityName": "Mountain View"},
			"asn":  map[string]any{"organization": "Google LLC"},
		})
	}))
	defer server.Close()
	client := New(server.URL, "tok", true)
	client.HTTPClient = server.Client()
	result, err := client.Lookup(context.Background(), "8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	if result.CountryISO != "US" || result.City != "Mountain View" || result.ASNOrg != "Google LLC" {
		t.Fatalf("%#v", result)
	}
	// cache
	_, _ = client.Lookup(context.Background(), "8.8.8.8")
}
