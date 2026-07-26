package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"collector/internal/analytics"
	"collector/internal/config"
	"collector/internal/store"

	"github.com/google/uuid"
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

func TestEquipmentTemplatesAPIUsesStableLabels(t *testing.T) {
	response := httptest.NewRecorder()
	(&Server{}).listEquipmentTemplates(response, httptest.NewRequest(http.MethodGet, "/", nil))
	body := response.Body.String()
	for _, value := range []string{
		`"key":"eltex-smg-1016m-3.410"`,
		`"displayName":"Eltex SMG-1016M (3.410)"`,
		`"key":"eltex-smg-1016m-3.23.2"`,
		`"displayName":"Eltex SMG-1016M (3.23.2)"`,
		`"key":"softswitch-cdr-raw-v1"`,
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("template response missing %s: %s", value, body)
		}
	}
}

func TestDeviceListRejectsInvalidCategoryBeforeDatabase(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/devices?category=invalid", nil)
	(&Server{}).listDevices(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "equipment or softswitch") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSanitizeDownloadName(t *testing.T) {
	tests := map[string]string{
		`../../secret.csv`: "secret.csv",
		`..\..\secret.csv`: "secret.csv",
		"bad\r\nname.csv":  "badname.csv",
		"":                 "cdr-file",
	}
	for input, want := range tests {
		if got := sanitizeDownloadName(input); got != want {
			t.Fatalf("sanitizeDownloadName(%q)=%q want %q", input, got, want)
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

func TestRetentionAPISynchronouslyReconcilesAndRefreshes(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	control, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	var cdrColumnsExists bool
	if err := control.DB.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='devices' AND column_name='cdr_columns'
	)`).Scan(&cdrColumnsExists); err != nil {
		t.Fatal(err)
	}
	if cdrColumnsExists {
		t.Fatal("cdr_columns remains after PostgreSQL migrations")
	}
	actor := store.User{ID: uuid.New(), Username: "retention-" + uuid.NewString(), Role: "admin"}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor.ID)
	})
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `UPDATE retention_policies SET
			active_days=1095,pending_days=NULL,effective_at=NULL,updated_by=NULL,last_error=NULL
			WHERE policy_class='syslog'`)
	})

	t.Run("success returns applied policy", func(t *testing.T) {
		if _, err := control.DB.Exec(ctx, `UPDATE retention_policies SET
			active_days=30,pending_days=NULL,effective_at=NULL,last_error=NULL
			WHERE policy_class='syslog'`); err != nil {
			t.Fatal(err)
		}
		called := false
		server := &Server{
			Store: control,
			ReconcileRetention: func(ctx context.Context) error {
				called = true
				policies, err := control.DueRetentionPolicies(ctx)
				if err != nil {
					return err
				}
				for _, policy := range policies {
					if policy.PolicyClass == "syslog" {
						return control.CompleteRetentionPolicy(
							ctx, policy.PolicyClass, *policy.PendingDays, policy.UpdatedAt,
						)
					}
				}
				return errors.New("updated policy was not due")
			},
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
			strings.NewReader(`{"policyClass":"syslog","days":14}`))
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: actor}))
		server.updateRetention(response, request)
		if !called || response.Code != http.StatusOK {
			t.Fatalf("called=%v status=%d body=%s", called, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"activeDays":14`) ||
			!strings.Contains(response.Body.String(), `"pendingDays":null`) {
			t.Fatalf("response was not refreshed: %s", response.Body.String())
		}
	})

	t.Run("failure remains pending", func(t *testing.T) {
		if _, err := control.DB.Exec(ctx, `UPDATE retention_policies SET
			active_days=30,pending_days=NULL,effective_at=NULL,last_error=NULL
			WHERE policy_class='syslog'`); err != nil {
			t.Fatal(err)
		}
		applyErr := errors.New("clickhouse unavailable")
		server := &Server{
			Store: control,
			ReconcileRetention: func(ctx context.Context) error {
				policies, err := control.DueRetentionPolicies(ctx)
				if err != nil {
					return err
				}
				for _, policy := range policies {
					if policy.PolicyClass == "syslog" {
						if err := control.FailRetentionPolicy(
							ctx, policy.PolicyClass, policy.UpdatedAt, applyErr,
						); err != nil {
							return err
						}
						return applyErr
					}
				}
				return errors.New("updated policy was not due")
			},
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
			strings.NewReader(`{"policyClass":"syslog","days":14}`))
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: actor}))
		server.updateRetention(response, request)
		if response.Code != http.StatusBadGateway {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"pendingDays":14`) ||
			!strings.Contains(response.Body.String(), `"lastError":"clickhouse unavailable"`) {
			t.Fatalf("failure response was not refreshed: %s", response.Body.String())
		}
		policies, err := control.ListRetentionPolicies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, policy := range policies {
			if policy.PolicyClass == "syslog" {
				if policy.PendingDays == nil || *policy.PendingDays != 14 ||
					policy.LastError == nil || *policy.LastError != applyErr.Error() {
					t.Fatalf("failed policy was not preserved: %+v", policy)
				}
				return
			}
		}
		t.Fatal("syslog policy not found")
	})

	t.Run("failed pending change can be cancelled", func(t *testing.T) {
		called := false
		server := &Server{
			Store: control,
			ReconcileRetention: func(context.Context) error {
				called = true
				return nil
			},
		}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPatch, "/api/system/retention",
			strings.NewReader(`{"policyClass":"syslog","cancel":true}`))
		request = request.WithContext(context.WithValue(request.Context(), sessionKey,
			store.Session{User: actor}))
		server.updateRetention(response, request)
		if !called || response.Code != http.StatusOK {
			t.Fatalf("called=%v status=%d body=%s", called, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"pendingDays":null`) ||
			!strings.Contains(response.Body.String(), `"lastError":null`) {
			t.Fatalf("cancel response was not refreshed: %s", response.Body.String())
		}
	})
}
