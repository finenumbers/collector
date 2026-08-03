package analytics

// ProjectionHealthSLOSeconds is the per-device live-tip health budget for Custom
// projection. Historical bucket catch-up age is not this budget.
const ProjectionHealthSLOSeconds int64 = 300

// ProjectionDeviceHealthInput is the queue + tip snapshot used to separate
// live projection health from traffic tip age and historical catch-up.
type ProjectionDeviceHealthInput struct {
	// BucketDepth is pending/running bucket jobs only. Eternal discover must not
	// count as backlog, or quiet SMGs never look idle.
	BucketDepth         uint64
	Failed              uint64
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

// EvaluateProjectionDeviceHealth decides SLO from live tip / failures, not
// frozen tip clocks on discover-only devices and not oldest historical
// bucket created_at (catch-up age).
func EvaluateProjectionDeviceHealth(in ProjectionDeviceHealthInput) ProjectionDeviceHealth {
	tipLag := in.WatermarkLagSeconds
	if in.AFCallLagSeconds > tipLag {
		tipLag = in.AFCallLagSeconds
	}
	var healthLag int64
	if in.BucketDepth > 0 {
		// Live tip while real hour work exists: cutover + AF tip freshness.
		healthLag = in.ActivatedLagSeconds
		if in.AFCallLagSeconds > healthLag {
			healthLag = in.AFCallLagSeconds
		}
	}
	sloMet := in.Failed == 0 && !in.ClassificationGap &&
		(in.BucketDepth == 0 || healthLag <= ProjectionHealthSLOSeconds)
	return ProjectionDeviceHealth{
		HealthLagSeconds:     healthLag,
		EventTipLagSeconds:   tipLag,
		ProjectionLagSeconds: healthLag,
		ProjectionSLOMet:     sloMet,
	}
}
