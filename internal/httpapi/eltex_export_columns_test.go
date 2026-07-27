package httpapi

import (
	"testing"
	"time"

	"collector/internal/analytics"
)

func TestEltexCallExportColumnsAlign(t *testing.T) {
	headers := eltexCallExportHeaders()
	values := eltexCallExportValues(analytics.CallRow{}, time.UTC)
	if len(headers) != len(values) {
		t.Fatalf("headers=%d values=%d", len(headers), len(values))
	}
	if len(headers) < 40 {
		t.Fatalf("expected full typed Eltex export, got %d columns", len(headers))
	}
}
