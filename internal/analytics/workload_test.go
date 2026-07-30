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

func TestCustomReconcileMemoryMatchesProjectionFloor(t *testing.T) {
	_, _, memory, _, _ := workloadQueryLimits(workload.CustomReconcile)
	if memory < 1024<<20 {
		t.Fatalf("custom_reconcile memory=%d, want at least 1GiB (UI maxMemoryBytes used to be ignored here)", memory)
	}
}

func TestProjectionMemoryBytesRaisesCustomReplay(t *testing.T) {
	client := &Client{}
	client.ConfigureWorkloads(WorkloadOptions{ProjectionMemoryBytes: 1536 << 20})
	_, _, memory, _, _ := client.workloadQueryLimits(workload.CustomReplay)
	if memory != 1536<<20 {
		t.Fatalf("custom_replay memory=%d, want 1536MiB from projection.maxMemoryBytes", memory)
	}
	_, _, floor, _, _ := workloadQueryLimits(workload.CustomReplay)
	client.ConfigureWorkloads(WorkloadOptions{ProjectionMemoryBytes: int64(floor / 2)})
	_, _, lowered, _, _ := client.workloadQueryLimits(workload.CustomReplay)
	if lowered != floor {
		t.Fatalf("custom_replay memory=%d, want floor %d (settings must not lower CH limit)", lowered, floor)
	}
}
