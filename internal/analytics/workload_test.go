package analytics

import (
	"testing"

	"collector/internal/workload"
)

func TestInteractiveWorkloadMemoryAllowsDenseCallCards(t *testing.T) {
	_, _, memory, _, _ := workloadQueryLimits(workload.Interactive)
	if memory < 512<<20 {
		t.Fatalf("interactive memory=%d, want at least 512MiB for dense AF FINAL lookups", memory)
	}
}
