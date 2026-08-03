package analytics

import "testing"

func TestEvaluateProjectionDeviceHealthQuietIdleOK(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 0, Failed: 0,
		WatermarkLagSeconds: 7594, AFCallLagSeconds: 7600,
		ActivatedLagSeconds: 5,
	})
	if !got.ProjectionSLOMet {
		t.Fatalf("discover-only/idle must meet SLO, got %+v", got)
	}
	if got.HealthLagSeconds != 0 {
		t.Fatalf("health lag = %d, want 0", got.HealthLagSeconds)
	}
	if got.EventTipLagSeconds != 7600 {
		t.Fatalf("tip lag = %d, want 7600", got.EventTipLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthIgnoresOldestBucketAge(t *testing.T) {
	// 25h historical catch-up must not paint health lag when live tip is fresh.
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 94, Failed: 0,
		ActivatedLagSeconds: 50, AFCallLagSeconds: 120,
		WatermarkLagSeconds: 200,
	})
	if !got.ProjectionSLOMet {
		t.Fatalf("fresh live tip during catch-up must meet SLO, got %+v", got)
	}
	if got.HealthLagSeconds != 120 {
		t.Fatalf("health lag = %d, want AF tip 120", got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthLiveTipBreach(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 3, Failed: 0,
		ActivatedLagSeconds: 10, AFCallLagSeconds: 400,
	})
	if got.ProjectionSLOMet {
		t.Fatalf("stale AF tip with bucket work must breach, got %+v", got)
	}
	if got.HealthLagSeconds != 400 {
		t.Fatalf("health lag = %d, want 400", got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthActivatedBreach(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 2, Failed: 0,
		ActivatedLagSeconds: 400, AFCallLagSeconds: 30,
	})
	if got.ProjectionSLOMet {
		t.Fatal("stale activated lag with bucket work must breach")
	}
	if got.HealthLagSeconds != 400 {
		t.Fatalf("health lag = %d, want activated 400", got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthFailedBreach(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 0, Failed: 1, AFCallLagSeconds: 0,
	})
	if got.ProjectionSLOMet {
		t.Fatal("failed jobs must breach even when idle")
	}
}

func TestEvaluateProjectionDeviceHealthClassificationGap(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 0, Failed: 0, ClassificationGap: true,
	})
	if got.ProjectionSLOMet {
		t.Fatal("classification gap must breach")
	}
}
