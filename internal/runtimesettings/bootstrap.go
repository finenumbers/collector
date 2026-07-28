package runtimesettings

import (
	"fmt"
	"time"

	"collector/internal/config"
)

// FromEnv builds a Document from process environment / config.Load defaults.
// Used once to seed an empty DB row; afterwards the UI/DB is authoritative.
func FromEnv(cfg config.Config) Document {
	doc := Defaults()
	doc.Projection.Enabled = cfg.CustomProjectionEnabled
	doc.Projection.Lookback = durationString(cfg.CustomProjectionLookback, doc.Projection.Lookback)
	doc.Projection.BatchSize = cfg.CustomProjectionBatchSize
	doc.Projection.MaxEvents = cfg.CustomProjectionMaxEvents
	doc.Projection.Threads = cfg.CustomProjectionThreads
	doc.Projection.MaxMemoryBytes = cfg.CustomProjectionMaxMemoryBytes
	doc.Projection.Sleep = durationString(cfg.CustomProjectionSleep, doc.Projection.Sleep)
	doc.Projection.Lease = durationString(cfg.CustomProjectionLease, doc.Projection.Lease)
	doc.Projection.ResponseTimeout = durationString(cfg.CustomResponseTimeout, doc.Projection.ResponseTimeout)
	doc.Projection.PairingHorizon = durationString(cfg.CustomPairingHorizon, doc.Projection.PairingHorizon)
	doc.Projection.RetryHorizon = durationString(cfg.CustomRetryHorizon, doc.Projection.RetryHorizon)
	doc.Projection.AssemblyIdle = durationString(cfg.CustomAssemblyIdle, doc.Projection.AssemblyIdle)

	doc.Coverage.ExpectedGrace = durationString(cfg.CoverageExpectedGrace, doc.Coverage.ExpectedGrace)
	doc.Coverage.LateThreshold = durationString(cfg.CoverageLateThreshold, doc.Coverage.LateThreshold)
	doc.Coverage.MissingTerminal = durationString(cfg.CoverageMissingTerminal, doc.Coverage.MissingTerminal)
	doc.Coverage.RetryHorizon = durationString(cfg.CoverageRetryHorizon, doc.Coverage.RetryHorizon)
	doc.Coverage.WorkerSleep = durationString(cfg.CoverageWorkerSleep, doc.Coverage.WorkerSleep)

	doc.Voipmonitor.Enabled = cfg.VoipmonitorEnabled
	doc.Voipmonitor.APIURL = cfg.VoipmonitorAPIURL
	doc.Voipmonitor.User = cfg.VoipmonitorUser
	doc.Voipmonitor.Password = cfg.VoipmonitorPassword
	doc.Voipmonitor.GUIURL = cfg.VoipmonitorGUIURL
	doc.Voipmonitor.CardURLTemplate = cfg.VoipmonitorCardURLTemplate
	doc.Voipmonitor.CallIDWindow = durationString(cfg.VoipmonitorCallIDWindow, doc.Voipmonitor.CallIDWindow)
	doc.Voipmonitor.FallbackWindow = durationString(cfg.VoipmonitorFallbackWindow, doc.Voipmonitor.FallbackWindow)
	doc.Voipmonitor.FallbackWindowMax = durationString(cfg.VoipmonitorFallbackWindowMax, doc.Voipmonitor.FallbackWindowMax)
	doc.Voipmonitor.WorkerSleep = durationString(cfg.VoipmonitorWorkerSleep, doc.Voipmonitor.WorkerSleep)
	doc.Voipmonitor.Lease = durationString(cfg.VoipmonitorLease, doc.Voipmonitor.Lease)
	doc.Voipmonitor.MinScore = cfg.VoipmonitorMinScore
	doc.Voipmonitor.DisambiguityMargin = cfg.VoipmonitorDisambiguityMargin
	doc.Voipmonitor.NumberSuffixLen = cfg.VoipmonitorNumberSuffixLen
	doc.Voipmonitor.RateLimitPerSec = cfg.VoipmonitorRateLimitPerSec
	doc.Voipmonitor.UseShareURL = cfg.VoipmonitorUseShareURL

	doc.Platform.ClickHouseAdmissionCapacity = cfg.ClickHouseAdmissionCapacity
	doc.Platform.ExportPageSize = cfg.ExportPageSize
	doc.Containers = containersFromEnv()
	return doc
}

func durationString(value time.Duration, fallback string) string {
	if value <= 0 {
		return fallback
	}
	return formatDuration(value)
}

func formatDuration(value time.Duration) string {
	if value%time.Hour == 0 && value >= time.Hour {
		return fmt.Sprintf("%dh", int64(value/time.Hour))
	}
	if value%time.Minute == 0 && value >= time.Minute {
		return fmt.Sprintf("%dm", int64(value/time.Minute))
	}
	if value%time.Second == 0 && value >= time.Second {
		return fmt.Sprintf("%ds", int64(value/time.Second))
	}
	return value.String()
}
