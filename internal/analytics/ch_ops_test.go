package analytics

import (
	"context"
	"strings"
	"testing"

	"collector/internal/workload"
)

func TestFreshWorkloadQueryIDUniquePerCall(t *testing.T) {
	ctx := context.WithValue(context.Background(), workloadClassKey{}, workload.CustomReplay)
	a := freshWorkloadQueryID(ctx)
	b := freshWorkloadQueryID(ctx)
	if a == "" || b == "" || a == b {
		t.Fatalf("expected unique non-empty query ids, got %q and %q", a, b)
	}
	if !strings.HasPrefix(a, "collector-custom_replay-") {
		t.Fatalf("unexpected query id prefix: %q", a)
	}
	plain := freshWorkloadQueryID(context.Background())
	if !strings.HasPrefix(plain, "collector-ch-") {
		t.Fatalf("default class prefix: %q", plain)
	}
}
