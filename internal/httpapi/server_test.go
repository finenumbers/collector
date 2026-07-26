package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"collector/internal/analytics"
	"collector/internal/config"
	"collector/internal/store"
)

func TestRevisionDiagnosticsAreIncludedInAPIResponse(t *testing.T) {
	response := make(map[string]any)
	addRevisionDiagnostics(response, analytics.SyslogDiagnostics{
		ActiveRevision: 1, BuildingRevision: 2, RevisionTimezone: "Asia/Novosibirsk",
		RevisionStatus: "building", ReplayProcessed: 10, ReplayTotal: 20,
		CDRReplayProcessed: 3, CDRReplayTotal: 4, MissingCDRTimes: 1,
		RadiusRawFragments: 30, LifecycleDerived: 12, CorrelationTotal: 12,
		CorrelationOrphan: 2,
	})
	required := []string{
		"activeRevision", "buildingRevision", "revisionTimezone", "revisionStatus",
		"replayProcessed", "replayTotal", "cdrReplayProcessed", "cdrReplayTotal",
		"missingCdrInterpretations", "radiusRawFragments", "lifecycleDerived",
		"correlationTotal", "correlationOrphan",
	}
	for _, key := range required {
		if _, ok := response[key]; !ok {
			t.Fatalf("diagnostics response is missing %q", key)
		}
	}
}

func TestConstructAPIReportsDisabledFeature(t *testing.T) {
	server := &Server{Config: config.Config{SyslogConstructsEnabled: false}}
	for _, handler := range []http.HandlerFunc{
		server.listSyslogConstructs,
		server.getSyslogConstruct,
	} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("got status %d, want 404", response.Code)
		}
		if !strings.Contains(response.Body.String(), `"error":"feature_disabled"`) {
			t.Fatalf("unexpected response: %s", response.Body.String())
		}
	}
}

func TestDashboardWindowValidation(t *testing.T) {
	for _, value := range []string{"", "1h", "24h", "7d"} {
		if _, err := analytics.ValidateDashboardWindow(value); err != nil {
			t.Fatalf("valid window %q failed: %v", value, err)
		}
	}
	for _, value := range []string{"2h", "0h", "168h"} {
		if _, err := analytics.ValidateDashboardWindow(value); err == nil {
			t.Fatalf("invalid window %q was accepted", value)
		}
	}
}

func TestDashboardAPIRejectsInvalidWindowBeforeQueries(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/dashboard?window=2h", nil)
	(&Server{}).dashboard(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", response.Code)
	}
	if !strings.Contains(response.Body.String(), "window must be one of") {
		t.Fatalf("unexpected response: %s", response.Body.String())
	}
}

func TestRetentionAPIValidatesInputBeforeDatabase(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "unknown class", body: `{"policyClass":"unknown","days":30}`,
			want: "invalid retention policy class"},
		{name: "too short", body: `{"policyClass":"syslog","days":6}`,
			want: "retention days must be between 7 and 1095"},
		{name: "too long", body: `{"policyClass":"cdr","days":1096}`,
			want: "retention days must be between 7 and 1095"},
	}
	server := &Server{Store: nil}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
				strings.NewReader(test.body))
			request = request.WithContext(context.WithValue(request.Context(), sessionKey,
				store.Session{User: store.User{Role: "admin"}}))
			server.updateRetention(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("got status %d, want 400", response.Code)
			}
			if !strings.Contains(response.Body.String(), test.want) {
				t.Fatalf("unexpected response: %s", response.Body.String())
			}
		})
	}
}

func TestRetentionRoutesRemainAdminOnly(t *testing.T) {
	handler := (&Server{}).requireAdmin(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		role string
		want int
	}{
		{role: "viewer", want: http.StatusForbidden},
		{role: "analyst", want: http.StatusForbidden},
		{role: "admin", want: http.StatusNoContent},
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention", nil)
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: store.User{Role: test.role}}))
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("role %s got status %d, want %d", test.role, response.Code, test.want)
		}
	}
}
