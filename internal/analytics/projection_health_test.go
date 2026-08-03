package analytics

import "testing"

func TestEvaluateProjectionDeviceHealthQuietIdleOK(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		Depth: 0, Failed: 0,
		WatermarkLagSeconds: 7594, AFCallLagSeconds: 7600,
		ActivatedLagSeconds: 5,
	})
	if !got.ProjectionSLOMet {
		t.Fatalf("quiet idle must meet SLO, got %+v", got)
	}
	if got.HealthLagSeconds != 0 {
		t.Fatalf("health lag = %d, want 0", got.HealthLagSeconds)
	}
	if got.EventTipLagSeconds != 7600 {
		t.Fatalf("tip lag = %d, want 7600", got.EventTipLagSeconds)
	}
	if got.ProjectionLagSeconds != 0 {
		t.Fatalf("projection lag display = %d, want health 0", got.ProjectionLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthBacklogBreach(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		Depth: 3, Failed: 0,
		OldestBucketAgeSec: 400, ActivatedLagSeconds: 10,
		WatermarkLagSeconds: 50, AFCallLagSeconds: 50,
	})
	if got.ProjectionSLOMet {
		t.Fatalf("backlog health lag must breach, got %+v", got)
	}
	if got.HealthLagSeconds != 400 {
		t.Fatalf("health lag = %d, want 400", got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthFailedBreach(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		Depth: 0, Failed: 1, WatermarkLagSeconds: 0,
	})
	if got.ProjectionSLOMet {
		t.Fatal("failed jobs must breach even when idle")
	}
}

func TestEvaluateProjectionDeviceHealthClassificationGap(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		Depth: 0, Failed: 0, ClassificationGap: true,
	})
	if got.ProjectionSLOMet {
		t.Fatal("classification gap must breach")
	}
}

func TestEvaluateProjectionDeviceHealthHealthyBacklog(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		Depth: 2, Failed: 0,
		OldestBucketAgeSec: 120, ActivatedLagSeconds: 30,
		WatermarkLagSeconds: 9000, AFCallLagSeconds: 9000,
	})
	if !got.ProjectionSLOMet {
		t.Fatalf("fresh backlog work must meet SLO, got %+v", got)
	}
	if got.HealthLagSeconds != 120 {
		t.Fatalf("health lag = %d, want 120", got.HealthLagSeconds)
	}
}
