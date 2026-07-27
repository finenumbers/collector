package httpapi

import (
	"context"
	"net/http"
	"time"

	"collector/internal/analytics"
	"collector/internal/store"
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
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if s.diagnosticsLoad != nil {
		value, err := s.diagnosticsLoad(ctx)
		s.finishDiagnostics(done, value, err)
		return
	}
	warehouse := analytics.OperationalDiagnostics{}
	projection := store.CustomProjectionQueueStats{}
	reconciliation := store.ReconciliationQueueStats{}
	var warehouseErr, projectionErr, reconciliationErr error
	if s.Config.CustomProjectionEnabled {
		warehouse, warehouseErr = s.Analytics.OperationalDiagnostics(ctx)
		projection, projectionErr = s.Store.CustomProjectionQueueStats(ctx)
		reconciliation, reconciliationErr = s.Store.ReconciliationQueueStats(ctx)
	}
	exports, exportErr := s.Store.ExportQueueStats(ctx)
	var refreshErr error
	for _, err := range []error{warehouseErr, projectionErr, reconciliationErr, exportErr} {
		if err != nil {
			refreshErr = err
			break
		}
	}
	var rawIngest any
	if s.Metrics != nil {
		rawIngest = s.Metrics.Snapshot()
	}
	value := map[string]any{
		"generatedAt":             time.Now().UTC(),
		"customProjectionEnabled": s.Config.CustomProjectionEnabled,
		"workloads":               s.Analytics.WorkloadSnapshot(),
		"rawIngest":               rawIngest,
		"projectionQueue": map[string]any{
			"depth": projection.Depth, "oldestAge": projection.OldestAge,
			"failed": projection.Failed, "backfilling": projection.Backfilling,
			"lagSeconds": warehouse.ProjectionLagSeconds,
		},
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
