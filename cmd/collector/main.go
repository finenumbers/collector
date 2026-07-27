package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"collector/internal/analytics"
	"collector/internal/archive"
	"collector/internal/config"
	"collector/internal/customprojection"
	"collector/internal/exportworker"
	ftpclient "collector/internal/ftp"
	"collector/internal/httpapi"
	"collector/internal/ingest"
	"collector/internal/reconciliation"
	"collector/internal/retention"
	"collector/internal/spool"
	"collector/internal/store"

	"github.com/nats-io/nats.go"
)

var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuration invalid", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if len(os.Args) > 1 && os.Args[1] == "migration-preflight" {
		if err := runMigrationPreflight(ctx, cfg); err != nil {
			slog.Error("migration preflight failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if cfg.Role == "ingress" {
		if err := runIngress(ctx, cfg); err != nil {
			slog.Error("Syslog ingress stopped", "error", err)
			os.Exit(1)
		}
		return
	}
	runAPIIngest := cfg.Role == "app" || cfg.Role == "api-ingest"
	runExport := cfg.Role == "app" || cfg.Role == "export"
	runMaintenance := cfg.Role == "app" || cfg.Role == "maintenance"

	control, err := openPostgres(ctx, cfg.PostgresURL)
	if err != nil {
		slog.Error("postgres startup failed", "error", err)
		os.Exit(1)
	}
	defer control.DB.Close()
	var activeLegacyJobs uint64
	if runAPIIngest {
		activeLegacyJobs, err = control.ActiveLegacySyslogParserJobs(ctx)
		if err != nil {
			slog.Error("legacy parser rebuild preflight failed", "error", err)
			os.Exit(1)
		}
		if activeLegacyJobs != 0 {
			slog.Error("legacy parser rebuild jobs are active; cleanup refused",
				"active_jobs", activeLegacyJobs)
			os.Exit(1)
		}
		if err := control.Migrate(ctx, "/app/migrations/postgres"); err != nil {
			slog.Error("postgres migration failed", "error", err)
			os.Exit(1)
		}
	}

	warehouse, err := openClickHouse(ctx, cfg)
	if err != nil {
		slog.Error("clickhouse startup failed", "error", err)
		os.Exit(1)
	}
	if runAPIIngest {
		if err := warehouse.Migrate(ctx, "/app/migrations/clickhouse", analytics.MigrationOptions{
			LegacyParserJobsChecked: true,
			ActiveLegacyParserJobs:  activeLegacyJobs,
			DeploymentLocker:        control,
			RequireDeploymentLock:   true,
		}); err != nil {
			slog.Error("clickhouse migration failed", "error", err)
			os.Exit(1)
		}
	}
	rawArchive, err := openArchive(ctx, cfg)
	if err != nil {
		slog.Error("object archive startup failed", "error", err)
		os.Exit(1)
	}
	if err := control.SetCustomProjectionGlobalEnabled(
		ctx, cfg.CustomProjectionEnabled, cfg.CustomProjectionLookback,
	); err != nil {
		slog.Error("custom projection global gate setup failed", "error", err)
		os.Exit(1)
	}
	retentionReconciler := &retention.Reconciler{
		Store: control, Analytics: warehouse, Archive: rawArchive,
	}
	if runAPIIngest || runMaintenance {
		if err := retentionReconciler.Run(ctx); err != nil {
			slog.Error("startup retention reconciliation failed", "error", err)
		}
	}
	if runExport {
		if err := rawArchive.ApplyExportRetention(ctx); err != nil {
			slog.Error("export retention setup failed", "error", err)
			os.Exit(1)
		}
	}

	var nc *nats.Conn
	var durableSpool *spool.Queue
	if runAPIIngest {
		nc, err = nats.Connect(cfg.NATSURL,
			nats.Name("eltex-collector"), nats.Timeout(10*time.Second), nats.MaxReconnects(-1))
		if err != nil {
			slog.Error("NATS startup failed", "error", err)
			os.Exit(1)
		}
		defer nc.Drain()
		if err := ingest.EnsureStreams(nc); err != nil {
			slog.Error("NATS stream setup failed", "error", err)
			os.Exit(1)
		}
		durableSpool, err = spool.Open(cfg.SyslogSpoolPath)
		if err != nil {
			slog.Error("durable spool startup failed", "error", err)
			os.Exit(1)
		}
		defer durableSpool.Close()
	}
	ingestMetrics := &ingest.Metrics{}
	exportHealth := &exportworker.Health{}
	var apiExportHealth *exportworker.Health
	if cfg.Role == "app" {
		apiExportHealth = exportHealth
	}

	apiServer := &httpapi.Server{
		Config: cfg, Store: control, Analytics: warehouse,
		FTP:                ftpclient.NewProvisioner(cfg.SFTPGoURL, cfg.SFTPGoAdmin, cfg.SFTPGoPassword),
		Archive:            rawArchive,
		StaticDir:          "/app/web",
		Version:            version,
		Metrics:            ingestMetrics,
		Spool:              durableSpool,
		NATS:               nc,
		IngressStatusPath:  cfg.IngressStatusPath,
		ExportHealth:       apiExportHealth,
		ReconcileRetention: retentionReconciler.RunNow,
	}
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Synchronous SMG purge can wait on ClickHouse mutations for several minutes.
		WriteTimeout:   16 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}

	errs := make(chan error, 8)
	if runAPIIngest {
		go func() {
			slog.Info("HTTP server listening", "address", cfg.HTTPAddr)
			errs <- server.ListenAndServe()
		}()
		go func() {
			slog.Info("Syslog handoff receiver listening", "socket", cfg.HandoffSocketPath)
			errs <- ingest.RunHandoffReceiver(
				ctx, cfg.HandoffSocketPath, control, durableSpool, ingestMetrics,
			)
		}()
		go func() {
			errs <- ingest.RunSpoolPublisher(ctx, durableSpool, nc)
		}()
		go func() {
			errs <- ingest.RunSyslogWorker(
				ctx, nc, warehouse, control, cfg.CustomProjectionEnabled,
			)
		}()
		go func() {
			watcher := ingest.CDRWatcher{
				Root: "/data/cdr", Store: control, Analytics: warehouse, Archive: rawArchive,
				CoverageThresholds: analytics.CoverageThresholds{
					ExpectedGrace:   cfg.CoverageExpectedGrace,
					LateThreshold:   cfg.CoverageLateThreshold,
					MissingTerminal: cfg.CoverageMissingTerminal,
					RetryHorizon:    cfg.CoverageRetryHorizon,
				},
				CustomProjectionEnabled: cfg.CustomProjectionEnabled,
			}
			errs <- watcher.Run(ctx)
		}()
	}
	hostname, _ := os.Hostname()
	if runMaintenance && cfg.CustomProjectionEnabled {
		projectionWorker := &customprojection.Worker{
			Queue: control, Warehouse: warehouse,
			Config: customprojection.Config{
				WorkerID:        fmt.Sprintf("%s-%d-custom", hostname, os.Getpid()),
				BatchSize:       cfg.CustomProjectionBatchSize,
				MaxEvents:       cfg.CustomProjectionMaxEvents,
				Threads:         cfg.CustomProjectionThreads,
				MaxMemoryBytes:  cfg.CustomProjectionMaxMemoryBytes,
				Sleep:           cfg.CustomProjectionSleep,
				Lease:           cfg.CustomProjectionLease,
				ResponseTimeout: cfg.CustomResponseTimeout,
				PairingHorizon:  cfg.CustomPairingHorizon,
				RetryHorizon:    cfg.CustomRetryHorizon,
				AssemblyIdle:    cfg.CustomAssemblyIdle,
			},
		}
		go func() {
			if err := projectionWorker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errs <- err
			}
		}()
		reconciliationWorker := &reconciliation.Worker{
			Store: warehouse, Queue: control,
			Config: reconciliation.Config{
				ExpectedGrace:   cfg.CoverageExpectedGrace,
				LateThreshold:   cfg.CoverageLateThreshold,
				MissingTerminal: cfg.CoverageMissingTerminal,
				RetryHorizon:    cfg.CoverageRetryHorizon,
			},
			Sleep:    cfg.CoverageWorkerSleep,
			Lease:    cfg.CustomProjectionLease,
			WorkerID: fmt.Sprintf("%s-%d-reconcile", hostname, os.Getpid()),
		}
		go func() {
			if err := reconciliationWorker.Run(ctx); err != nil &&
				!errors.Is(err, context.Canceled) {
				errs <- err
			}
		}()
	}
	if runExport {
		exportWorker := &exportworker.Worker{
			Store: control, Archive: rawArchive,
			WorkerID: fmt.Sprintf("%s-%d", hostname, os.Getpid()),
			SpoolDir: "/data/spool", Render: apiServer.AsyncExportRenderer(), Health: exportHealth,
		}
		go func() {
			if err := exportWorker.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errs <- err
			}
		}()
	}
	if runMaintenance {
		go func() {
			ticker := time.NewTicker(time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := retentionReconciler.Run(ctx); err != nil &&
						!errors.Is(err, context.Canceled) {
						slog.Error("retention reconciliation failed", "error", err)
					}
				}
			}
		}()
	}
	select {
	case <-ctx.Done():
		slog.Info("shutdown requested")
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("component stopped", "error", err)
		}
		stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if runAPIIngest {
		_ = server.Shutdown(shutdownCtx)
	}
}

func runMigrationPreflight(ctx context.Context, cfg config.Config) error {
	control, err := openPostgres(ctx, cfg.PostgresURL)
	if err != nil {
		return err
	}
	defer control.DB.Close()
	activeJobs, err := control.ActiveLegacySyslogParserJobs(ctx)
	if err != nil {
		return err
	}
	warehouse, err := openClickHouse(ctx, cfg)
	if err != nil {
		return err
	}
	options := analytics.MigrationOptions{
		LegacyParserJobsChecked: true,
		ActiveLegacyParserJobs:  activeJobs,
		StopBeforeCleanup:       true,
		DeploymentLocker:        control,
		RequireDeploymentLock:   true,
	}
	if err := warehouse.Migrate(ctx, "/app/migrations/clickhouse", options); err != nil {
		return err
	}
	report, err := warehouse.PreflightLegacySyslogCleanup(ctx, options)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	return report.Validate()
}

func runIngress(ctx context.Context, cfg config.Config) error {
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	queue, err := spool.Open(cfg.IngressSpoolPath)
	if err != nil {
		return err
	}
	defer queue.Close()
	metrics := &ingest.Metrics{}
	health := &http.Server{
		Addr: cfg.IngressHealthAddr,
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			status, _ := ingest.ReadIngressStatus(cfg.IngressStatusPath)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"status": "ok", "role": "ingress", "version": version, "ingress": status,
			})
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errs := make(chan error, 5)
	var workers sync.WaitGroup
	start := func(run func() error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			errs <- run()
		}()
	}
	start(func() error {
		receiver := ingest.IngressReceiver{Addr: cfg.SyslogAddr, Spool: queue, Metrics: metrics}
		slog.Info("source-preserving Syslog ingress listening", "address", cfg.SyslogAddr)
		return receiver.Run(runCtx)
	})
	start(func() error {
		return ingest.RunIngressHandoffPublisher(runCtx, queue, cfg.HandoffSocketPath, metrics)
	})
	start(func() error {
		return ingest.RunIngressStatusWriter(runCtx, cfg.IngressStatusPath, queue, metrics)
	})
	start(func() error {
		return ingest.RunIngressPurgeControl(runCtx, cfg.IngressControlPath, queue)
	})
	start(func() error {
		slog.Info("Syslog ingress health server listening", "address", cfg.IngressHealthAddr)
		return health.ListenAndServe()
	})
	var componentErr error
	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			componentErr = err
		}
	}
	cancelRun()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := health.Shutdown(shutdownCtx); err != nil && componentErr == nil {
		componentErr = err
	}
	stopped := make(chan struct{})
	go func() {
		workers.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-shutdownCtx.Done():
		if componentErr == nil {
			componentErr = shutdownCtx.Err()
		}
	}
	return componentErr
}

func openPostgres(ctx context.Context, url string) (*store.Store, error) {
	var result *store.Store
	var err error
	for attempt := 1; attempt <= 30; attempt++ {
		result, err = store.Open(ctx, url)
		if err == nil {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, err
}

func openClickHouse(ctx context.Context, cfg config.Config) (*analytics.Client, error) {
	var result *analytics.Client
	var err error
	for attempt := 1; attempt <= 30; attempt++ {
		result, err = analytics.Open(cfg.ClickHouseAddr, cfg.ClickHouseDB, cfg.ClickHouseUser, cfg.ClickHousePass)
		if err == nil {
			result.ConfigureWorkloads(analytics.WorkloadOptions{
				Capacity: cfg.ClickHouseAdmissionCapacity,
			})
			return result, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, err
}

func openArchive(ctx context.Context, cfg config.Config) (*archive.Archive, error) {
	var result *archive.Archive
	var err error
	for attempt := 1; attempt <= 30; attempt++ {
		result, err = archive.Open(ctx, cfg.MinIOEndpoint, cfg.MinIOAccessKey, cfg.MinIOSecretKey, cfg.RawBucket, cfg.MinIOUseTLS)
		if err == nil {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return nil, err
}
