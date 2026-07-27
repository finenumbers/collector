package voipmonitor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAPIEndpointNormalization(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://vm.example.com", "https://vm.example.com/php/api.php"},
		{"https://vm.example.com/", "https://vm.example.com/php/api.php"},
		{"https://vm.example.com/php", "https://vm.example.com/php/api.php"},
		{"https://vm.example.com/php/", "https://vm.example.com/php/api.php"},
		{"https://vm.example.com/php/api.php", "https://vm.example.com/php/api.php"},
		{"https://vm.example.com/api.php", "https://vm.example.com/api.php"},
	}
	for _, test := range tests {
		got, err := apiEndpoint(test.in)
		if err != nil {
			t.Fatalf("%q: %v", test.in, err)
		}
		if got != test.want {
			t.Fatalf("%q => %q, want %q", test.in, got, test.want)
		}
	}
}

func TestParseVoipCallsResponseErrorEnvelope(t *testing.T) {
	_, err := parseVoipCallsResponse([]byte(
		`{"error":"unhandled request","msg":"unhandled request","success":false}`,
	))
	if err == nil || !strings.Contains(err.Error(), "unhandled request") {
		t.Fatalf("expected unhandled request error, got %v", err)
	}
}

func TestParseVoipCallsResponseNoMatchIsEmpty(t *testing.T) {
	calls, err := parseVoipCallsResponse([]byte(
		`{"error":"no match cdr","msg":"no match cdr","success":false}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("calls %#v", calls)
	}
}

func TestGetVoipCallsFormEncoded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("method %s", req.Method)
		}
		if ct := req.Header.Get("Content-Type"); !strings.Contains(ct, "application/x-www-form-urlencoded") {
			t.Fatalf("content-type %q", ct)
		}
		body, _ := io.ReadAll(req.Body)
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Fatal(err)
		}
		if values.Get("task") != "getVoipCalls" || values.Get("user") != "u" || values.Get("password") != "p" {
			t.Fatalf("form %#v", values)
		}
		if !strings.Contains(values.Get("params"), `"callId":"abc"`) {
			t.Fatalf("params %q", values.Get("params"))
		}
		_, _ = writer.Write([]byte(`[{"cdrId":"9","callId":"abc","caller":"1","called":"2"}]`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, User: "u", Password: "p", HTTPClient: server.Client()}
	calls, err := client.GetVoipCalls(context.Background(), map[string]any{
		"startTime": "2026-07-27 00:00:00", "callId": "abc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].CDRID != "9" || calls[0].CallID != "abc" {
		t.Fatalf("calls %#v", calls)
	}
}
