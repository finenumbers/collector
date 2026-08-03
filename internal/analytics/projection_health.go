package analytics

// ProjectionHealthSLOSeconds is the per-device health lag budget for Custom
// projection. Tip ages (last AF event / watermark) are not this budget.
const ProjectionHealthSLOSeconds int64 = 300

// ProjectionDeviceHealthInput is the queue + tip snapshot used to separate
// projection health from traffic tip age on quiet SMGs.
type ProjectionDeviceHealthInput struct {
	Depth               uint64
	Failed              uint64
	OldestBucketAgeSec  int64
	ActivatedLagSeconds int64
	WatermarkLagSeconds int64
	AFCallLagSeconds    int64
	ClassificationGap   bool
}

// ProjectionDeviceHealth is the operator-facing health vs tip split.
type ProjectionDeviceHealth struct {
	HealthLagSeconds     int64
	EventTipLagSeconds   int64
	ProjectionLagSeconds int64
	ProjectionSLOMet     bool
}

// EvaluateProjectionDeviceHealth decides SLO from real backlog/failures, not
// frozen tip clocks on idle quiet devices.
func EvaluateProjectionDeviceHealth(in ProjectionDeviceHealthInput) ProjectionDeviceHealth {
	tipLag := in.WatermarkLagSeconds
	if in.AFCallLagSeconds > tipLag {
		tipLag = in.AFCallLagSeconds
	}
	var healthLag int64
	if in.Depth > 0 {
		healthLag = in.ActivatedLagSeconds
		if in.OldestBucketAgeSec > healthLag {
			healthLag = in.OldestBucketAgeSec
		}
	}
	sloMet := in.Failed == 0 && !in.ClassificationGap &&
		(in.Depth == 0 || healthLag <= ProjectionHealthSLOSeconds)
	return ProjectionDeviceHealth{
		HealthLagSeconds:     healthLag,
		EventTipLagSeconds:   tipLag,
		ProjectionLagSeconds: healthLag,
		ProjectionSLOMet:     sloMet,
	}
}
