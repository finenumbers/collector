package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
	durableSpool, err := spool.Open("/data/spool/syslog.db")
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
			FTP:       ftpclient.NewProvisioner(cfg.SFTPGoURL, cfg.SFTPGoAdmin, cfg.SFTPGoPassword),
			StaticDir: "/app/web",
			Version:   version,
			Metrics:   ingestMetrics,
			Spool:     durableSpool,
			NATS:      nc,
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
		receiver := ingest.SyslogReceiver{
			Addr: cfg.SyslogAddr, Store: control, Spool: durableSpool, Metrics: ingestMetrics,
		}
		slog.Info("syslog receiver listening", "address", cfg.SyslogAddr)
		errs <- receiver.Run(ctx)
	}()
	go func() {
		errs <- ingest.RunSpoolPublisher(ctx, durableSpool, nc)
	}()
	go func() {
		errs <- ingest.RunSyslogWorker(ctx, nc, warehouse)
	}()
	go func() {
		watcher := ingest.CDRWatcher{
			Root: "/data/cdr", Store: control, Analytics: warehouse, Archive: rawArchive,
		}
		errs <- watcher.Run(ctx)
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
