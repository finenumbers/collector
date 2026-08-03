package analytics

import "testing"

func TestEvaluateProjectionDeviceHealthQuietIdleOK(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 0, Failed: 0,
		WatermarkLagSeconds: 7594, AFCallLagSeconds: 7600,
		AFSyslogLagSeconds: 7600, HasAFSyslogTip: true,
		ActivatedLagSeconds: 5,
	})
	if !got.ProjectionSLOMet {
		t.Fatalf("discover-only/idle must meet SLO, got %+v", got)
	}
	if got.HealthLagSeconds != 0 {
		t.Fatalf("health lag = %d, want 0", got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthMoscowQuietCatchUpOK(t *testing.T) {
	// Sparse Moscow: last call 1660s ago, AF syslog tip equally old, cutovers fresh.
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 7, Failed: 0,
		ActivatedLagSeconds: 243,
		AFCallLagSeconds:    1660,
		AFSyslogLagSeconds:  1660,
		HasAFSyslogTip:      true,
		WatermarkLagSeconds: 500,
	})
	if !got.ProjectionSLOMet {
		t.Fatalf("quiet mid-catch-up must meet SLO, got %+v", got)
	}
	if got.ContentLagSeconds != 0 {
		t.Fatalf("content lag = %d, want 0", got.ContentLagSeconds)
	}
	if got.HealthLagSeconds != 243 {
		t.Fatalf("health lag = %d, want activated 243", got.HealthLagSeconds)
	}
	if got.EventTipLagSeconds != 1660 {
		t.Fatalf("event tip = %d, want AF tip 1660 (informational)", got.EventTipLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthRealContentStall(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 3, Failed: 0,
		ActivatedLagSeconds: 10,
		AFCallLagSeconds:    1660,
		AFSyslogLagSeconds:  50,
		HasAFSyslogTip:      true,
	})
	if got.ProjectionSLOMet {
		t.Fatalf("AF syslog ahead of projected calls must breach, got %+v", got)
	}
	if got.ContentLagSeconds != 1610 {
		t.Fatalf("content lag = %d, want 1610", got.ContentLagSeconds)
	}
	if got.HealthLagSeconds != 1610 {
		t.Fatalf("health lag = %d, want content 1610", got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthActivatedBreach(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 2, Failed: 0,
		ActivatedLagSeconds: 400,
		AFCallLagSeconds:    30,
		AFSyslogLagSeconds:  30,
		HasAFSyslogTip:      true,
	})
	if got.ProjectionSLOMet {
		t.Fatal("stale activated lag with bucket work must breach")
	}
	if got.HealthLagSeconds != 400 {
		t.Fatalf("health lag = %d, want activated 400", got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthNoAFSyslogTip(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 5, Failed: 0,
		ActivatedLagSeconds: 100,
		AFCallLagSeconds:    9000,
		HasAFSyslogTip:      false,
	})
	if !got.ProjectionSLOMet {
		t.Fatalf("no AF syslog tip must not invent content debt, got %+v", got)
	}
	if got.ContentLagSeconds != 0 || got.HealthLagSeconds != 100 {
		t.Fatalf("got content=%d health=%d", got.ContentLagSeconds, got.HealthLagSeconds)
	}
}

func TestEvaluateProjectionDeviceHealthFailedBreach(t *testing.T) {
	got := EvaluateProjectionDeviceHealth(ProjectionDeviceHealthInput{
		BucketDepth: 0, Failed: 1,
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

func TestContentLagSeconds(t *testing.T) {
	if got := ContentLagSeconds(1660, 1660, true); got != 0 {
		t.Fatalf("quiet content lag = %d", got)
	}
	if got := ContentLagSeconds(100, 200, true); got != 0 {
		t.Fatalf("calls ahead of syslog = %d", got)
	}
	if got := ContentLagSeconds(1660, 50, false); got != 0 {
		t.Fatalf("no tip = %d", got)
	}
}
