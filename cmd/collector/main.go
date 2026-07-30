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
	"collector/internal/geoiplookup"
	"collector/internal/httpapi"
	"collector/internal/ingest"
	"collector/internal/lookuptelemetry"
	"collector/internal/pstnlookup"
	"collector/internal/reconciliation"
	"collector/internal/retention"
	"collector/internal/runtimesettings"
	"collector/internal/spool"
	"collector/internal/store"
	"collector/internal/voipmonitor"

	"github.com/google/uuid"
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
	if len(os.Args) > 1 && (os.Args[1] == "satel-enrich" || os.Args[1] == "pstn-enrich-satel") {
		if err := runSatelEnrich(ctx, cfg); err != nil {
			slog.Error("satel enrich failed", "error", err)
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
	runtimeDoc, err := control.EnsureRuntimeSettings(ctx, runtimesettings.FromEnv(cfg))
	if err != nil {
		slog.Error("runtime settings bootstrap failed", "error", err)
		os.Exit(1)
	}
	runtime := runtimesettings.NewManager(runtimeDoc)
	applyProjectionGate := func(doc runtimesettings.Document) {
		if err := control.SetCustomProjectionGlobalEnabled(
			ctx, doc.Projection.Enabled, runtimesettings.MustDuration(doc.Projection.Lookback),
		); err != nil {
			slog.Error("custom projection global gate setup failed", "error", err)
		}
	}
	applyClickHouseAdmission := func(doc runtimesettings.Document) {
		// Replaces the admission manager; in-flight queries keep their current
		// lease/limits until they finish, while new queries use the new capacity.
		warehouse.ConfigureWorkloads(analytics.WorkloadOptions{
			Capacity: doc.Platform.ClickHouseAdmissionCapacity,
		})
	}
	applyProjectionGate(runtimeDoc)
	applyClickHouseAdmission(runtimeDoc)
	if err := writeContainerLimitsEnv("/data/spool/container-limits.env", runtimeDoc); err != nil {
		slog.Error("container limits env write failed", "error", err)
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
	// In-process Health is authoritative only when this process runs the export
	// worker. Split api-ingest infers liveness from export_jobs heartbeats.
	if runExport {
		apiExportHealth = exportHealth
	}
	var cdrWatcher *ingest.CDRWatcher
	enrichRT := &enrichmentRuntime{}
	applyEnrichmentClients := func(doc runtimesettings.Document) {
		pstn := pstnlookup.New(doc.Enrichment.PSTN.APIURL, doc.Enrichment.PSTN.Token, doc.Enrichment.PSTN.Enabled)
		geoip := geoiplookup.New(doc.Enrichment.GeoIP.APIURL, doc.Enrichment.GeoIP.Token, doc.Enrichment.GeoIP.Enabled)
		workers := doc.Enrichment.Workers
		if workers < 1 {
			workers = 24
		}
		lookuptelemetry.Default.SetState("pstn", pstn.Enabled(), doc.Enrichment.PSTN.Token != "")
		lookuptelemetry.Default.SetState("geoip", geoip.Enabled(), doc.Enrichment.GeoIP.Token != "")
		enrichRT.set(pstn, geoip, workers)
		if cdrWatcher != nil {
			cdrWatcher.SetEnrichmentClients(pstn, geoip, workers)
		}
	}
	applyRuntimeDocument := func(doc runtimesettings.Document) {
		runtime.Replace(doc)
		applyProjectionGate(doc)
		applyClickHouseAdmission(doc)
		applyEnrichmentClients(doc)
		if err := writeContainerLimitsEnv("/data/spool/container-limits.env", doc); err != nil {
			slog.Error("container limits env write failed", "error", err)
		}
		slog.Info("runtime settings applied",
			"projectionEnabled", doc.Projection.Enabled,
			"projectionThreads", doc.Projection.Threads,
			"voipmonitorEnabled", doc.Voipmonitor.Enabled,
			"pstnEnrichmentEnabled", doc.Enrichment.PSTN.Enabled && doc.Enrichment.PSTN.Token != "",
			"geoipEnrichmentEnabled", doc.Enrichment.GeoIP.Enabled && doc.Enrichment.GeoIP.Token != "",
			"enrichmentWorkers", doc.Enrichment.Workers,
			"enrichmentCatchUp", doc.Enrichment.CatchUp.Enabled,
			"clickhouseAdmissionCapacity", doc.Platform.ClickHouseAdmissionCapacity,
			"apiMemory", doc.Containers.APIMemory)
	}
	applyEnrichmentClients(runtime.Snapshot())

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
		Runtime:            runtime,
		OnRuntimeSettingsChanged: func(doc runtimesettings.Document) {
			applyRuntimeDocument(doc)
		},
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
	// Split maintenance/export processes do not receive PATCH callbacks; poll PG
	// so local Manager + ClickHouse admission hot-apply without restart. The API
	// process also polls as a backstop when another replica wrote settings.
	go watchRuntimeSettings(ctx, control, runtime, applyRuntimeDocument)
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
				ctx, nc, warehouse, control, func() bool {
					return runtime.Snapshot().Projection.Enabled
				},
			)
		}()
		cdrWatcher = &ingest.CDRWatcher{
			Root: "/data/cdr", Store: control, Analytics: warehouse, Archive: rawArchive,
			CoverageThresholdsFn: func() analytics.CoverageThresholds {
				return coverageThresholds(runtime.Snapshot())
			},
			CustomProjectionEnabledFn: func() bool {
				return runtime.Snapshot().Projection.Enabled
			},
		}
		applyEnrichmentClients(runtime.Snapshot())
		go func() {
			errs <- cdrWatcher.Run(ctx)
		}()
	}
	hostname, _ := os.Hostname()
	if runMaintenance {
		go runProjectionSupervisor(ctx, runtime, control, warehouse, hostname, errs)
		go runReconciliationSupervisor(ctx, runtime, control, warehouse, hostname, errs)
		go runVoipmonitorSupervisor(ctx, runtime, control, warehouse, hostname, errs)
		go runEnrichmentCatchUp(ctx, runtime, warehouse, enrichRT)
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

func runSatelEnrich(ctx context.Context, cfg config.Config) error {
	control, err := openPostgres(ctx, cfg.PostgresURL)
	if err != nil {
		return err
	}
	doc, err := control.EnsureRuntimeSettings(ctx, runtimesettings.FromEnv(cfg))
	if err != nil {
		return err
	}
	pstn := pstnlookup.New(doc.Enrichment.PSTN.APIURL, doc.Enrichment.PSTN.Token, doc.Enrichment.PSTN.Enabled)
	geoip := geoiplookup.New(doc.Enrichment.GeoIP.APIURL, doc.Enrichment.GeoIP.Token, doc.Enrichment.GeoIP.Enabled)
	if !pstn.Enabled() && !geoip.Enabled() {
		return fmt.Errorf("enable PSTN and/or GeoIP enrichment with tokens in Настройки → Параметры")
	}
	warehouse, err := openClickHouse(ctx, cfg)
	if err != nil {
		return err
	}
	pageSize := uint64(doc.Enrichment.CatchUp.PageSize)
	if pageSize == 0 {
		pageSize = 1000
	}
	workers := doc.Enrichment.Workers
	after := uuid.Nil
	var totalRows int
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		records, err := warehouse.ListSatelRTURecordsNeedingEnrichment(ctx, pageSize, after)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			break
		}
		written, err := enrichAndWriteSatelPage(ctx, warehouse, pstn, geoip, records, workers)
		if err != nil {
			return err
		}
		totalRows += written
		after = records[len(records)-1].RecordID
		slog.Info("satel enrich progress",
			"enriched", totalRows, "page", len(records), "written", written,
			"workers", workers, "lastRecordId", after.String())
		if uint64(len(records)) < pageSize {
			break
		}
	}
	slog.Info("satel enrich complete", "rows", totalRows)
	return nil
}

type enrichmentRuntime struct {
	mu      sync.RWMutex
	pstn    *pstnlookup.Client
	geoip   *geoiplookup.Client
	workers int
}

func (e *enrichmentRuntime) set(pstn *pstnlookup.Client, geoip *geoiplookup.Client, workers int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pstn, e.geoip, e.workers = pstn, geoip, workers
}

func (e *enrichmentRuntime) get() (*pstnlookup.Client, *geoiplookup.Client, int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pstn, e.geoip, e.workers
}

func enrichAndWriteSatelPage(
	ctx context.Context, warehouse *analytics.Client,
	pstn *pstnlookup.Client, geoip *geoiplookup.Client,
	records []analytics.SatelRTURecord, workers int,
) (int, error) {
	analytics.EnrichSatelRecords(ctx, pstn, geoip, records, workers)
	now := time.Now().UTC()
	toInsert := make([]analytics.SatelRTURecord, 0, len(records))
	for _, record := range records {
		if record.BillANIOperator == "" && record.BillDNISOperator == "" &&
			record.BillANIRegion == "" && record.BillDNISRegion == "" &&
			record.RemoteSrcGeoipISO == "" && record.RemoteDstGeoipISO == "" &&
			record.RemoteSrcGeoipCity == "" && record.RemoteDstGeoipCity == "" &&
			record.RemoteSrcASNOrg == "" && record.RemoteDstASNOrg == "" {
			continue
		}
		record.IngestedAt = now
		toInsert = append(toInsert, record)
	}
	if len(toInsert) == 0 {
		return 0, nil
	}
	if err := warehouse.InsertSatelRTUBatch(ctx, toInsert); err != nil {
		return 0, err
	}
	return len(toInsert), nil
}

func runEnrichmentCatchUp(
	ctx context.Context,
	runtime *runtimesettings.Manager,
	warehouse *analytics.Client,
	enrichRT *enrichmentRuntime,
) {
	after := uuid.Nil
	for ctx.Err() == nil {
		doc := runtime.Snapshot()
		sleepFor := runtimesettings.MustDuration(doc.Enrichment.CatchUp.Sleep)
		if sleepFor <= 0 {
			sleepFor = 2 * time.Second
		}
		if !doc.Enrichment.CatchUp.Enabled {
			after = uuid.Nil
			if !sleepContext(ctx, sleepFor) {
				return
			}
			continue
		}
		pstn, geoip, workers := enrichRT.get()
		if (pstn == nil || !pstn.Enabled()) && (geoip == nil || !geoip.Enabled()) {
			if !sleepContext(ctx, sleepFor) {
				return
			}
			continue
		}
		pageSize := uint64(doc.Enrichment.CatchUp.PageSize)
		if pageSize == 0 {
			pageSize = 1000
		}
		records, err := warehouse.ListSatelRTURecordsNeedingEnrichment(ctx, pageSize, after)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Error("enrichment catch-up list failed", "error", err)
			if !sleepContext(ctx, sleepFor) {
				return
			}
			continue
		}
		if len(records) == 0 {
			after = uuid.Nil
			if !sleepContext(ctx, sleepFor) {
				return
			}
			continue
		}
		written, err := enrichAndWriteSatelPage(ctx, warehouse, pstn, geoip, records, workers)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			slog.Error("enrichment catch-up write failed", "error", err)
			if !sleepContext(ctx, sleepFor) {
				return
			}
			continue
		}
		after = records[len(records)-1].RecordID
		slog.Info("enrichment catch-up progress",
			"page", len(records), "written", written, "workers", workers,
			"lastRecordId", after.String())
		if uint64(len(records)) < pageSize {
			after = uuid.Nil
			if !sleepContext(ctx, sleepFor) {
				return
			}
		}
		// Busy backlog: continue immediately to the next page.
	}
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

func runProjectionSupervisor(
	ctx context.Context,
	runtime *runtimesettings.Manager,
	control *store.Store,
	warehouse *analytics.Client,
	hostname string,
	errs chan<- error,
) {
	workerID := fmt.Sprintf("%s-%d-custom", hostname, os.Getpid())
	var lastFP string
	for ctx.Err() == nil {
		doc := runtime.Snapshot()
		fp := fmt.Sprintf("%t/%d", doc.Projection.Enabled, doc.Projection.Threads)
		if !doc.Projection.Enabled {
			lastFP = fp
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		if fp == lastFP {
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		lastFP = fp
		runCtx, cancel := context.WithCancel(ctx)
		worker := &customprojection.Worker{
			Queue: control, Warehouse: warehouse,
			ConfigFn: func() customprojection.Config {
				return projectionConfig(runtime.Snapshot(), workerID)
			},
		}
		done := make(chan error, 1)
		go func() { done <- worker.Run(runCtx) }()
		for ctx.Err() == nil {
			next := runtime.Snapshot()
			nextFP := fmt.Sprintf("%t/%d", next.Projection.Enabled, next.Projection.Threads)
			if nextFP != lastFP {
				cancel()
				<-done
				break
			}
			select {
			case err := <-done:
				cancel()
				if err != nil && !errors.Is(err, context.Canceled) {
					errs <- err
					return
				}
				lastFP = ""
			case <-time.After(time.Second):
			case <-ctx.Done():
				cancel()
				<-done
				return
			}
		}
		cancel()
	}
}

func runReconciliationSupervisor(
	ctx context.Context,
	runtime *runtimesettings.Manager,
	control *store.Store,
	warehouse *analytics.Client,
	hostname string,
	errs chan<- error,
) {
	workerID := fmt.Sprintf("%s-%d-reconcile", hostname, os.Getpid())
	var lastFP string
	for ctx.Err() == nil {
		doc := runtime.Snapshot()
		fp := fmt.Sprintf("%t/%s/%s/%s/%s/%s/%s",
			doc.Projection.Enabled, doc.Coverage.WorkerSleep, doc.Projection.Lease,
			doc.Coverage.ExpectedGrace, doc.Coverage.LateThreshold,
			doc.Coverage.MissingTerminal, doc.Coverage.RetryHorizon)
		if !doc.Projection.Enabled {
			lastFP = fp
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		if fp == lastFP {
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		lastFP = fp
		runCtx, cancel := context.WithCancel(ctx)
		snap := runtime.Snapshot()
		worker := &reconciliation.Worker{
			Store: warehouse, Queue: control,
			Config:   reconciliationConfig(snap),
			Sleep:    runtimesettings.MustDuration(snap.Coverage.WorkerSleep),
			Lease:    runtimesettings.MustDuration(snap.Projection.Lease),
			WorkerID: workerID,
		}
		done := make(chan error, 1)
		go func() { done <- worker.Run(runCtx) }()
		for ctx.Err() == nil {
			next := runtime.Snapshot()
			nextFP := fmt.Sprintf("%t/%s/%s/%s/%s/%s/%s",
				next.Projection.Enabled, next.Coverage.WorkerSleep, next.Projection.Lease,
				next.Coverage.ExpectedGrace, next.Coverage.LateThreshold,
				next.Coverage.MissingTerminal, next.Coverage.RetryHorizon)
			if nextFP != lastFP {
				cancel()
				<-done
				break
			}
			select {
			case err := <-done:
				cancel()
				if err != nil && !errors.Is(err, context.Canceled) {
					errs <- err
					return
				}
				lastFP = ""
			case <-time.After(time.Second):
			case <-ctx.Done():
				cancel()
				<-done
				return
			}
		}
		cancel()
	}
}

func runVoipmonitorSupervisor(
	ctx context.Context,
	runtime *runtimesettings.Manager,
	control *store.Store,
	warehouse *analytics.Client,
	hostname string,
	errs chan<- error,
) {
	workerID := fmt.Sprintf("%s-%d-voipmonitor", hostname, os.Getpid())
	var lastFP string
	for ctx.Err() == nil {
		doc := runtime.Snapshot()
		fp := runtimesettings.FingerprintWorkers(doc)
		if !doc.Voipmonitor.Enabled {
			lastFP = fp
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		if fp == lastFP {
			if !sleepContext(ctx, time.Second) {
				return
			}
			continue
		}
		lastFP = fp
		runCtx, cancel := context.WithCancel(ctx)
		snap := runtime.Snapshot()
		worker := &voipmonitor.Worker{
			Store: warehouse, Queue: control,
			Matcher:  voipmonitorMatcher(snap),
			Sleep:    runtimesettings.MustDuration(snap.Voipmonitor.WorkerSleep),
			Lease:    runtimesettings.MustDuration(snap.Voipmonitor.Lease),
			Lookback: runtimesettings.MustDuration(snap.Projection.Lookback),
			WorkerID: workerID,
		}
		done := make(chan error, 1)
		go func() { done <- worker.Run(runCtx) }()
		for ctx.Err() == nil {
			nextFP := runtimesettings.FingerprintWorkers(runtime.Snapshot())
			if nextFP != lastFP {
				cancel()
				<-done
				break
			}
			select {
			case err := <-done:
				cancel()
				if err != nil && !errors.Is(err, context.Canceled) {
					errs <- err
					return
				}
				lastFP = ""
			case <-time.After(time.Second):
			case <-ctx.Done():
				cancel()
				<-done
				return
			}
		}
		cancel()
	}
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// watchRuntimeSettings polls PostgreSQL so split maintenance/export processes
// hot-apply settings written by the API role without process restart.
func watchRuntimeSettings(
	ctx context.Context,
	control *store.Store,
	runtime *runtimesettings.Manager,
	onChange func(runtimesettings.Document),
) {
	var lastUpdated time.Time
	if row, err := control.LoadRuntimeSettings(ctx); err == nil {
		lastUpdated = row.UpdatedAt
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			row, err := control.LoadRuntimeSettings(ctx)
			if err != nil || !row.Seeded || !row.UpdatedAt.After(lastUpdated) {
				continue
			}
			lastUpdated = row.UpdatedAt
			if onChange != nil {
				onChange(row.Settings)
			} else {
				runtime.Replace(row.Settings)
			}
		}
	}
}

func writeContainerLimitsEnv(path string, doc runtimesettings.Document) error {
	return os.WriteFile(path, []byte(doc.Containers.ComposeEnvFragment()), 0o644)
}
