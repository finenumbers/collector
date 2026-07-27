package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCustomProjectionGlobalGateRejectsStaleReads(t *testing.T) {
	server := &Server{}
	request := httptest.NewRequest(http.MethodGet, "/api/devices/unused/antifraud-calls", nil)
	response := httptest.NewRecorder()
	server.listAntifraudCalls(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}
