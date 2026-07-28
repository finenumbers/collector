package main

import (
	"collector/internal/analytics"
	"collector/internal/customprojection"
	"collector/internal/reconciliation"
	"collector/internal/runtimesettings"
	"collector/internal/voipmonitor"
)

func projectionConfig(doc runtimesettings.Document, workerID string) customprojection.Config {
	return customprojection.Config{
		WorkerID:        workerID,
		BatchSize:       doc.Projection.BatchSize,
		MaxEvents:       doc.Projection.MaxEvents,
		Threads:         doc.Projection.Threads,
		MaxMemoryBytes:  doc.Projection.MaxMemoryBytes,
		Sleep:           runtimesettings.MustDuration(doc.Projection.Sleep),
		Lease:           runtimesettings.MustDuration(doc.Projection.Lease),
		ResponseTimeout: runtimesettings.MustDuration(doc.Projection.ResponseTimeout),
		PairingHorizon:  runtimesettings.MustDuration(doc.Projection.PairingHorizon),
		RetryHorizon:    runtimesettings.MustDuration(doc.Projection.RetryHorizon),
		AssemblyIdle:    runtimesettings.MustDuration(doc.Projection.AssemblyIdle),
	}
}

func coverageThresholds(doc runtimesettings.Document) analytics.CoverageThresholds {
	return analytics.CoverageThresholds{
		ExpectedGrace:   runtimesettings.MustDuration(doc.Coverage.ExpectedGrace),
		LateThreshold:   runtimesettings.MustDuration(doc.Coverage.LateThreshold),
		MissingTerminal: runtimesettings.MustDuration(doc.Coverage.MissingTerminal),
		RetryHorizon:    runtimesettings.MustDuration(doc.Coverage.RetryHorizon),
	}
}

func reconciliationConfig(doc runtimesettings.Document) reconciliation.Config {
	thresholds := coverageThresholds(doc)
	return reconciliation.Config{
		ExpectedGrace:   thresholds.ExpectedGrace,
		LateThreshold:   thresholds.LateThreshold,
		MissingTerminal: thresholds.MissingTerminal,
		RetryHorizon:    thresholds.RetryHorizon,
	}
}

func voipmonitorMatcher(doc runtimesettings.Document) *voipmonitor.Matcher {
	return &voipmonitor.Matcher{
		Client: &voipmonitor.Client{
			BaseURL:         doc.Voipmonitor.APIURL,
			User:            doc.Voipmonitor.User,
			Password:        doc.Voipmonitor.Password,
			RateLimitPerSec: doc.Voipmonitor.RateLimitPerSec,
		},
		GUIBase:            doc.Voipmonitor.GUIURL,
		CardTpl:            doc.Voipmonitor.CardURLTemplate,
		CallIDWindow:       runtimesettings.MustDuration(doc.Voipmonitor.CallIDWindow),
		FallbackWindow:     runtimesettings.MustDuration(doc.Voipmonitor.FallbackWindow),
		FallbackWindowMax:  runtimesettings.MustDuration(doc.Voipmonitor.FallbackWindowMax),
		MinScore:           doc.Voipmonitor.MinScore,
		DisambiguityMargin: doc.Voipmonitor.DisambiguityMargin,
		NumberSuffixLen:    doc.Voipmonitor.NumberSuffixLen,
		UseShareURL:        doc.Voipmonitor.UseShareURL,
	}
}
