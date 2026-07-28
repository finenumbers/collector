package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"collector/internal/analytics"
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
	var warehouseErr, projectionErr, reconciliationErr, deviceErr, freshnessErr error
	if s.customProjectionEnabled() {
		warehouse, warehouseErr = s.Analytics.OperationalDiagnostics(ctx)
		projection, projectionErr = s.Store.CustomProjectionQueueStats(ctx)
		reconciliation, reconciliationErr = s.Store.ReconciliationQueueStats(ctx)
		deviceStats, deviceErr = s.Store.CustomProjectionDeviceStats(ctx)
		if deviceErr == nil && len(deviceStats) > 0 {
			ids := make([]uuid.UUID, 0, len(deviceStats))
			for _, item := range deviceStats {
				ids = append(ids, item.DeviceID)
			}
			freshness, freshnessErr = s.Analytics.DeviceProjectionFreshness(ctx, ids)
		}
	}
	exports, exportErr := s.Store.ExportQueueStats(ctx)
	var refreshErr error
	for _, err := range []error{
		warehouseErr, projectionErr, reconciliationErr, deviceErr, freshnessErr, exportErr,
	} {
		if err != nil {
			refreshErr = err
			break
		}
	}
	devices := make([]map[string]any, 0, len(deviceStats))
	var maxDeviceLag int64
	anyFailed := projection.Failed > 0
	anyGap := false
	allDeviceSLO := true
	for _, item := range deviceStats {
		tip := freshness[item.DeviceID]
		lag := item.WatermarkLagSeconds
		if tip.ActivatedLagSeconds > lag {
			lag = tip.ActivatedLagSeconds
		}
		if lag > maxDeviceLag {
			maxDeviceLag = lag
		}
		if item.Failed > 0 {
			anyFailed = true
		}
		if tip.ClassificationGap {
			anyGap = true
		}
		sloMet := lag <= 300 && item.Failed == 0 && !tip.ClassificationGap
		if !sloMet {
			allDeviceSLO = false
		}
		devices = append(devices, map[string]any{
			"deviceId":             item.DeviceID,
			"name":                 item.Name,
			"depth":                item.Depth,
			"failed":               item.Failed,
			"backfilling":          item.Backfilling,
			"oldestAge":            item.OldestAge,
			"watermarkState":       item.WatermarkState,
			"watermarkLagSeconds":  item.WatermarkLagSeconds,
			"lastError":            item.LastError,
			"syslogLagSeconds":     tip.SyslogLagSeconds,
			"afCallLagSeconds":     tip.AFCallLagSeconds,
			"activatedLagSeconds":  tip.ActivatedLagSeconds,
			"afAuthHeaders6h":      tip.AFAuthHeaders6h,
			"xpgkHeaders6h":        tip.XpgkHeaders6h,
			"classificationGap":    tip.ClassificationGap,
			"projectionLagSeconds": lag,
			"projectionSloMet":     sloMet,
		})
	}
	if len(deviceStats) > 0 {
		warehouse.MaxDeviceProjectionLagSeconds = maxDeviceLag
		warehouse.AnyDeviceFailed = anyFailed
		warehouse.AnyClassificationGap = anyGap
		warehouse.ProjectionSLOMet = allDeviceSLO && warehouse.ProjectionLagSeconds <= 300
	}
	var rawIngest any
	if s.Metrics != nil {
		rawIngest = s.Metrics.Snapshot()
	}
	value := map[string]any{
		"generatedAt":             time.Now().UTC(),
		"customProjectionEnabled": s.customProjectionEnabled(),
		"workloads":               s.Analytics.WorkloadSnapshot(),
		"rawIngest":               rawIngest,
		"projectionQueue": map[string]any{
			"depth": projection.Depth, "oldestAge": projection.OldestAge,
			"failed": projection.Failed, "backfilling": projection.Backfilling,
			"lagSeconds":           warehouse.ProjectionLagSeconds,
			"maxDeviceLagSeconds":  maxDeviceLag,
			"anyDeviceFailed":      anyFailed,
			"anyClassificationGap": anyGap,
		},
		"projectionDevices":   devices,
		"reconciliationQueue": reconciliation,
		"derived":             warehouse,
		"exports":             exports,
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
