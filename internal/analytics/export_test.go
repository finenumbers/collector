package analytics

import (
	"errors"
	"testing"
)

func TestNormalizeExportEstimateIsUnknownOnOverflowOrFailure(t *testing.T) {
	if value := normalizeExportEstimate(ExportEstimateLimit, nil); value == nil ||
		*value != ExportEstimateLimit {
		t.Fatalf("bounded estimate = %v", value)
	}
	if value := normalizeExportEstimate(ExportEstimateLimit+1, nil); value != nil {
		t.Fatalf("overflow estimate = %d, want unknown", *value)
	}
	if value := normalizeExportEstimate(10, errors.New("timeout")); value != nil {
		t.Fatalf("failed estimate = %d, want unknown", *value)
	}
}
