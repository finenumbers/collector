package main

import (
	"context"
	"encoding/json"
	"errors"
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
	ftpclient "collector/internal/ftp"
	"collector/internal/httpapi"
	"collector/internal/ingest"
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
	if cfg.Role == "ingress" {
		if err := runIngress(ctx, cfg); err != nil {
			slog.Error("Syslog ingress stopped", "error", err)
			os.Exit(1)
		}
		return
	}

	control, err := openPostgres(ctx, cfg.PostgresURL)
	if err != nil {
		slog.Error("postgres startup failed", "error", err)
		os.Exit(1)
	}
	defer control.DB.Close()
	if err := control.Migrate(ctx, "/app/migrations/postgres"); err != nil {
		slog.Error("postgres migration failed", "error", err)
		os.Exit(1)
	}

	warehouse, err := openClickHouse(ctx, cfg)
	if err != nil {
		slog.Error("clickhouse startup failed", "error", err)
		os.Exit(1)
	}
	if err := warehouse.Migrate(ctx, "/app/migrations/clickhouse"); err != nil {
		slog.Error("clickhouse migration failed", "error", err)
		os.Exit(1)
	}
	rawArchive, err := openArchive(ctx, cfg)
	if err != nil {
		slog.Error("object archive startup failed", "error", err)
		os.Exit(1)
	}

	nc, err := nats.Connect(cfg.NATSURL,
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
	durableSpool, err := spool.Open(cfg.SyslogSpoolPath)
	if err != nil {
		slog.Error("durable spool startup failed", "error", err)
		os.Exit(1)
	}
	defer durableSpool.Close()
	ingestMetrics := &ingest.Metrics{}

	server := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: (&httpapi.Server{
			Config: cfg, Store: control, Analytics: warehouse,
			FTP:               ftpclient.NewProvisioner(cfg.SFTPGoURL, cfg.SFTPGoAdmin, cfg.SFTPGoPassword),
			StaticDir:         "/app/web",
			Version:           version,
			Metrics:           ingestMetrics,
			Spool:             durableSpool,
			NATS:              nc,
			IngressStatusPath: cfg.IngressStatusPath,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	errs := make(chan error, 5)
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
		errs <- ingest.RunSyslogWorker(ctx, nc, warehouse, control)
	}()
	go func() {
		watcher := ingest.CDRWatcher{
			Root: "/data/cdr", Store: control, Analytics: warehouse, Archive: rawArchive,
		}
		errs <- watcher.Run(ctx)
	}()
	go func() {
		for ctx.Err() == nil {
			if err := ingest.RunDeviceRevisionRebuilds(ctx, warehouse, control); err != nil &&
				!errors.Is(err, context.Canceled) {
				slog.Error("versioned device rebuild failed; retrying", "error", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	go func() {
		for ctx.Err() == nil {
			buckets, err := warehouse.ListPendingCorrelationBuckets(ctx, 20)
			if err != nil {
				slog.Error("dirty correlation queue read failed", "error", err)
			} else {
				for _, bucket := range buckets {
					if err := warehouse.ReconcileDirtyBucket(ctx, bucket); err != nil {
						slog.Error("dirty correlation bucket failed",
							"device", bucket.DeviceID, "revision", bucket.Revision,
							"bucket", bucket.Bucket, "error", err)
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

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
	_ = server.Shutdown(shutdownCtx)
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
	errs := make(chan error, 4)
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
