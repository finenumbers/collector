package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"collector/internal/analytics"
	"collector/internal/lookuptelemetry"
	"collector/internal/store"

	"github.com/google/uuid"
)

const diagnosticsCacheTTL = 30 * time.Second

func (s *Server) systemDiagnostics(writer http.ResponseWriter, request *http.Request) {
	value, err := s.cachedDiagnostics(request.Context())
	if err != nil {
		if request.Context().Err() != nil {
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "operational diagnostics unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, value)
}

// cachedDiagnostics coalesces refreshes. The refresh has an independent bounded
// context, so cancellation of the request that became leader does not poison
// the result for other administrators.
func (s *Server) cachedDiagnostics(ctx context.Context) (map[string]any, error) {
	for {
		s.diagnosticsMu.Lock()
		if s.diagnosticsValue != nil && time.Since(s.diagnosticsAt) < diagnosticsCacheTTL {
			value, err := s.diagnosticsValue, s.diagnosticsErr
			s.diagnosticsMu.Unlock()
			return value, err
		}
		running := s.diagnosticsRunning
		if running == nil {
			running = make(chan struct{})
			s.diagnosticsRunning = running
			go s.refreshDiagnostics(running)
		}
		s.diagnosticsMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-running:
		}
	}
}

func (s *Server) refreshDiagnostics(done chan struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if s.diagnosticsLoad != nil {
		value, err := s.diagnosticsLoad(ctx)
		s.finishDiagnostics(done, value, err)
		return
	}
	warehouse := analytics.OperationalDiagnostics{}
	projection := store.CustomProjectionQueueStats{}
	reconciliation := store.ReconciliationQueueStats{}
	deviceStats := []store.CustomProjectionDeviceStats{}
	freshness := map[uuid.UUID]analytics.DeviceProjectionFreshness{}
	sectionErrors := map[string]string{}
	noteErr := func(key string, err error) {
		if err == nil {
			return
		}
		sectionErrors[key] = err.Error()
		log.Printf("diagnostics: %s: %v", key, err)
	}
	if s.customProjectionEnabled() {
		var warehouseErr, projectionErr, reconciliationErr, deviceErr, freshnessErr error
		warehouse, warehouseErr = s.Analytics.OperationalDiagnostics(ctx)
		noteErr("warehouse", warehouseErr)
		projection, projectionErr = s.Store.CustomProjectionQueueStats(ctx)
		noteErr("projection", projectionErr)
		reconciliation, reconciliationErr = s.Store.ReconciliationQueueStats(ctx)
		noteErr("reconciliation", reconciliationErr)
		deviceStats, deviceErr = s.Store.CustomProjectionDeviceStats(ctx)
		noteErr("devices", deviceErr)
		if deviceErr == nil && len(deviceStats) > 0 {
			ids := make([]uuid.UUID, 0, len(deviceStats))
			for _, item := range deviceStats {
				ids = append(ids, item.DeviceID)
			}
			freshness, freshnessErr = s.Analytics.DeviceProjectionFreshness(ctx, ids)
			noteErr("freshness", freshnessErr)
			if freshnessErr != nil {
				freshness = map[uuid.UUID]analytics.DeviceProjectionFreshness{}
			}
		}
	}
	exports, exportErr := s.Store.ExportQueueStats(ctx)
	noteErr("exports", exportErr)

	devices := make([]map[string]any, 0, len(deviceStats))
	var maxDeviceLag, maxEventTipLag int64
	anyFailed := projection.Failed > 0
	anyGap := false
	allDeviceSLO := true
	for _, item := range deviceStats {
		tip := freshness[item.DeviceID]
		health := analytics.EvaluateProjectionDeviceHealth(analytics.ProjectionDeviceHealthInput{
			BucketDepth:         item.BucketDepth,
			Failed:              item.Failed,
			ActivatedLagSeconds: tip.ActivatedLagSeconds,
			WatermarkLagSeconds: item.WatermarkLagSeconds,
			AFCallLagSeconds:    tip.AFCallLagSeconds,
			AFSyslogLagSeconds:  tip.AFSyslogLagSeconds,
			HasAFSyslogTip:      tip.HasAFSyslogTip,
			ClassificationGap:   tip.ClassificationGap,
		})
		if health.HealthLagSeconds > maxDeviceLag {
			maxDeviceLag = health.HealthLagSeconds
		}
		if health.EventTipLagSeconds > maxEventTipLag {
			maxEventTipLag = health.EventTipLagSeconds
		}
		if item.Failed > 0 {
			anyFailed = true
		}
		if tip.ClassificationGap {
			anyGap = true
		}
		if !health.ProjectionSLOMet {
			allDeviceSLO = false
		}
		devices = append(devices, map[string]any{
			"deviceId":             item.DeviceID,
			"name":                 item.Name,
			"depth":                item.Depth,
			"bucketDepth":          item.BucketDepth,
			"failed":               item.Failed,
			"backfilling":          item.Backfilling,
			"oldestAge":            item.OldestAge,
			"oldestBucketAge":      item.OldestBucketAge,
			"watermarkState":       item.WatermarkState,
			"watermarkLagSeconds":  item.WatermarkLagSeconds,
			"lastError":            item.LastError,
			"syslogLagSeconds":     tip.SyslogLagSeconds,
			"afCallLagSeconds":     tip.AFCallLagSeconds,
			"afSyslogLagSeconds":   tip.AFSyslogLagSeconds,
			"hasAFSyslogTip":       tip.HasAFSyslogTip,
			"activatedLagSeconds":  tip.ActivatedLagSeconds,
			"afAuthHeaders6h":      tip.AFAuthHeaders6h,
			"xpgkHeaders6h":        tip.XpgkHeaders6h,
			"classificationGap":    tip.ClassificationGap,
			"healthLagSeconds":     health.HealthLagSeconds,
			"contentLagSeconds":    health.ContentLagSeconds,
			"eventTipLagSeconds":   health.EventTipLagSeconds,
			"projectionLagSeconds": health.ProjectionLagSeconds,
			"projectionSloMet":     health.ProjectionSLOMet,
			"openHourStatus":       item.OpenHourStatus,
			"openHourAgeSeconds":   item.OpenHourAgeSeconds,
		})
	}
	if len(deviceStats) > 0 {
		warehouse.MaxDeviceProjectionLagSeconds = maxDeviceLag
		warehouse.AnyDeviceFailed = anyFailed
		warehouse.AnyClassificationGap = anyGap
		// Fleet projection SLO is per-device health, not global activated tip
		// or quiet-SMG event tip ages.
		warehouse.ProjectionSLOMet = allDeviceSLO
	}
	var rawIngest any
	if s.Metrics != nil {
		rawIngest = s.Metrics.Snapshot()
	}
	enrichmentApis := lookuptelemetry.Default.Snapshot()
	var enrichmentCoverage any
	if coverage, coverageErr := s.Analytics.EnrichmentCoverage(ctx, 24*3600); coverageErr == nil {
		enrichmentCoverage = coverage
	}
	enrichmentWorkers := 0
	enrichmentCatchUp := false
	if s.Runtime != nil {
		doc := s.Runtime.Snapshot()
		enrichmentWorkers = doc.Enrichment.Workers
		enrichmentCatchUp = doc.Enrichment.CatchUp.Enabled
	}
	degraded := len(sectionErrors) > 0
	value := map[string]any{
		"generatedAt":             time.Now().UTC(),
		"customProjectionEnabled": s.customProjectionEnabled(),
		"degraded":                degraded,
		"workloads":               s.Analytics.WorkloadSnapshot(),
		"rawIngest":               rawIngest,
		"enrichmentApis":          enrichmentApis,
		"enrichmentCoverage":      enrichmentCoverage,
		"enrichmentWorkers":       enrichmentWorkers,
		"enrichmentCatchUp":       enrichmentCatchUp,
		"projectionQueue": map[string]any{
			"depth": projection.Depth, "oldestAge": projection.OldestAge,
			"oldestBucketAge": projection.OldestBucketAge,
			"discoverAge":     projection.DiscoverAge,
			"failed":          projection.Failed, "backfilling": projection.Backfilling,
			"lagSeconds":            warehouse.ProjectionLagSeconds,
			"maxDeviceLagSeconds":   maxDeviceLag,
			"maxEventTipLagSeconds": maxEventTipLag,
			"anyDeviceFailed":       anyFailed,
			"anyClassificationGap":  anyGap,
		},
		"projectionDevices":   devices,
		"reconciliationQueue": reconciliation,
		"derived":             warehouse,
		"exports":             exports,
	}
	if degraded {
		value["errors"] = sectionErrors
	}
	// Always return partial payload; UI shows degraded/errors. Hard 503 only when
	// every section failed and we have no device/export/warehouse signal at all.
	var refreshErr error
	if degraded && exportErr != nil && len(deviceStats) == 0 && warehouse.Calls == 0 &&
		projection.Depth == 0 && reconciliation.Depth == 0 {
		refreshErr = errors.New("operational diagnostics unavailable")
	}
	s.finishDiagnostics(done, value, refreshErr)
}

func (s *Server) finishDiagnostics(done chan struct{}, value map[string]any, err error) {
	s.diagnosticsMu.Lock()
	s.diagnosticsValue, s.diagnosticsErr = value, err
	s.diagnosticsAt = time.Now()
	s.diagnosticsRunning = nil
	close(done)
	s.diagnosticsMu.Unlock()
}

func (s *Server) requeueFailedProjection(writer http.ResponseWriter, request *http.Request) {
	deviceID, ok := parseDeviceID(writer, request)
	if !ok {
		return
	}
	if _, err := s.Store.Device(request.Context(), deviceID); errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "device not found")
		return
	} else if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to load device")
		return
	}
	requeued, err := s.Store.RequeueFailedProjectionJobs(request.Context(), deviceID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to requeue failed projection jobs")
		return
	}
	overflow, err := s.Store.RequeueFailedOverflowProjectionJobs(request.Context())
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "unable to requeue overflow projection jobs")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"deviceId": deviceID, "requeued": requeued, "overflowRequeued": overflow,
	})
}
