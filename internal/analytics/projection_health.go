package analytics

// ProjectionHealthSLOSeconds is the per-device live health budget for Custom
// projection. Absolute AF tip age and historical catch-up age are not this budget.
const ProjectionHealthSLOSeconds int64 = 300

// ProjectionDeviceHealthInput is the queue + tip snapshot used to separate
// live projection health from sparse traffic tip age and historical catch-up.
type ProjectionDeviceHealthInput struct {
	// BucketDepth is pending/running bucket jobs only. Eternal discover must not
	// count as backlog, or quiet SMGs never look idle.
	BucketDepth         uint64
	Failed              uint64
	ActivatedLagSeconds int64
	WatermarkLagSeconds int64
	AFCallLagSeconds    int64
	AFSyslogLagSeconds  int64
	HasAFSyslogTip      bool
	ClassificationGap   bool
}

// ProjectionDeviceHealth is the operator-facing health vs tip split.
type ProjectionDeviceHealth struct {
	HealthLagSeconds     int64
	ContentLagSeconds    int64
	EventTipLagSeconds   int64
	ProjectionLagSeconds int64
	ProjectionSLOMet     bool
}

// ContentLagSeconds is how far projected AF calls lag behind the newest
// AF-classifiable syslog tip. Quiet SMGs with matching tip ages yield ~0.
func ContentLagSeconds(afCallLag, afSyslogLag int64, hasAFSyslogTip bool) int64 {
	if !hasAFSyslogTip {
		return 0
	}
	contentLag := afCallLag - afSyslogLag
	if contentLag < 0 {
		return 0
	}
	return contentLag
}

// EvaluateProjectionDeviceHealth decides SLO from cutover freshness and
// content debt vs AF syslog — never absolute last-call age alone.
func EvaluateProjectionDeviceHealth(in ProjectionDeviceHealthInput) ProjectionDeviceHealth {
	tipLag := in.WatermarkLagSeconds
	if in.AFCallLagSeconds > tipLag {
		tipLag = in.AFCallLagSeconds
	}
	contentLag := ContentLagSeconds(in.AFCallLagSeconds, in.AFSyslogLagSeconds, in.HasAFSyslogTip)
	var healthLag int64
	if in.BucketDepth > 0 {
		healthLag = in.ActivatedLagSeconds
		if contentLag > healthLag {
			healthLag = contentLag
		}
	}
	sloMet := in.Failed == 0 && !in.ClassificationGap &&
		(in.BucketDepth == 0 || healthLag <= ProjectionHealthSLOSeconds)
	return ProjectionDeviceHealth{
		HealthLagSeconds:     healthLag,
		ContentLagSeconds:    contentLag,
		EventTipLagSeconds:   tipLag,
		ProjectionLagSeconds: healthLag,
		ProjectionSLOMet:     sloMet,
	}
}
