package exportworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"collector/internal/archive"
	"collector/internal/store"
)

const (
	DefaultLease        = 45 * time.Second
	DefaultPoll         = 2 * time.Second
	DefaultMaxSpool     = int64(2 << 30)
	DefaultXLSXRowLimit = int64(250_000)
)

type Health struct {
	lastSuccess         atomic.Int64
	consecutiveFailures atomic.Uint64
	lastError           atomic.Value
}

func (h *Health) recordSuccess() {
	if h == nil {
		return
	}
	h.lastSuccess.Store(time.Now().UnixNano())
	h.consecutiveFailures.Store(0)
	h.lastError.Store("")
}

func (h *Health) recordFailure(err error) {
	if h == nil || err == nil {
		return
	}
	h.consecutiveFailures.Add(1)
	h.lastError.Store(err.Error())
}

func (h *Health) Available(maxAge time.Duration) bool {
	if h == nil {
		return true
	}
	value := h.lastSuccess.Load()
	return value != 0 && h.consecutiveFailures.Load() < 3 &&
		time.Since(time.Unix(0, value)) <= maxAge
}

func (h *Health) LastError() string {
	if h == nil {
		return ""
	}
	value := h.lastError.Load()
	if value == nil {
		return ""
	}
	return value.(string)
}

type ProgressFunc func(rows int64) error

type RenderResult struct {
	Rows        int64
	Format      string
	Filename    string
	ContentType string
}

type RenderFunc func(
	ctx context.Context, job store.ExportJob, output io.Writer, progress ProgressFunc,
) (RenderResult, error)

type Worker struct {
	Store    *store.Store
	Archive  *archive.Archive
	WorkerID string
	SpoolDir string
	Lease    time.Duration
	Poll     time.Duration
	MaxSpool int64
	Render   RenderFunc
	Health   *Health
	runOnce  func(context.Context) (bool, error)
}

type boundedWriter struct {
	writer  io.Writer
	written atomic.Int64
	limit   int64
}

func (w *boundedWriter) Write(value []byte) (int, error) {
	if w.written.Load()+int64(len(value)) > w.limit {
		return 0, fmt.Errorf("export exceeds spool limit of %d bytes", w.limit)
	}
	n, err := w.writer.Write(value)
	w.written.Add(int64(n))
	return n, err
}

func (w *Worker) defaults() {
	if w.Lease <= 0 {
		w.Lease = DefaultLease
	}
	if w.Poll <= 0 {
		w.Poll = DefaultPoll
	}
	if w.MaxSpool <= 0 {
		w.MaxSpool = DefaultMaxSpool
	}
	if w.SpoolDir == "" {
		w.SpoolDir = os.TempDir()
	}
}

// Run claims and executes exports until ctx is cancelled. It is intentionally
// not started by the HTTP server; the process owner controls its lifecycle.
func (w *Worker) Run(ctx context.Context) error {
	w.defaults()
	if w.Store == nil || w.Archive == nil || w.Render == nil || w.WorkerID == "" {
		return errors.New("export worker is not fully configured")
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
		iteration := w.RunOnce
		if w.runOnce != nil {
			iteration = w.runOnce
		}
		worked, err := iteration(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			w.Health.recordFailure(err)
			slog.Warn("async export worker iteration failed; retrying",
				"worker", w.WorkerID, "error", err, "retryAfter", w.Poll)
			worked = false
		} else {
			w.Health.recordSuccess()
		}
		delay := w.Poll
		if worked {
			delay = 0
		}
		timer.Reset(delay)
	}
}

func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	w.defaults()
	job, err := w.Store.ClaimExportJob(ctx, w.WorkerID, w.Lease)
	if errors.Is(err, store.ErrNotFound) {
		if cleanupErr := w.expire(ctx); cleanupErr != nil {
			return false, cleanupErr
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := w.execute(ctx, job); err != nil && !errors.Is(err, context.Canceled) {
		return true, nil // The job records its own terminal failure.
	}
	return true, nil
}

func (w *Worker) execute(ctx context.Context, job store.ExportJob) error {
	started := time.Now()
	slog.Info("async export started", "job", job.ID, "device", job.DeviceID,
		"dataset", job.Dataset, "queueAge", time.Since(job.CreatedAt))
	fail := func(failure error) error {
		_ = w.Store.FinishExportJob(
			context.WithoutCancel(ctx), job.ID, w.WorkerID, "failed", failure.Error(),
		)
		slog.Warn("async export failed", "job", job.ID, "device", job.DeviceID,
			"dataset", job.Dataset, "duration", time.Since(started), "error", failure)
		return failure
	}
	file, err := os.CreateTemp(w.SpoolDir, "collector-export-*.part")
	if err != nil {
		return fail(err)
	}
	name := file.Name()
	defer os.Remove(name)
	defer file.Close()

	writer := &boundedWriter{writer: file, limit: w.MaxSpool}
	renderCtx, cancelRender := context.WithCancel(ctx)
	defer cancelRender()
	var processedRows atomic.Int64
	var heartbeatErr error
	var heartbeatMu sync.Mutex
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(max(w.Lease/3, time.Second))
		defer ticker.Stop()
		for {
			select {
			case <-renderCtx.Done():
				return
			case <-ticker.C:
				cancelled, updateErr := w.Store.UpdateExportProgress(
					renderCtx, job.ID, w.WorkerID, processedRows.Load(), writer.written.Load(), w.Lease,
				)
				if updateErr != nil {
					w.Health.recordFailure(updateErr)
				} else {
					w.Health.recordSuccess()
				}
				if updateErr != nil || cancelled {
					heartbeatMu.Lock()
					heartbeatErr = updateErr
					if heartbeatErr == nil {
						heartbeatErr = context.Canceled
					}
					heartbeatMu.Unlock()
					cancelRender()
					return
				}
			}
		}
	}()
	progress := func(rows int64) error {
		processedRows.Store(rows)
		cancelled, updateErr := w.Store.UpdateExportProgress(
			renderCtx, job.ID, w.WorkerID, rows, writer.written.Load(), w.Lease,
		)
		if updateErr != nil {
			w.Health.recordFailure(updateErr)
			return updateErr
		}
		w.Health.recordSuccess()
		if cancelled {
			return context.Canceled
		}
		return renderCtx.Err()
	}
	result, renderErr := w.Render(renderCtx, job, writer, progress)
	if renderErr == nil {
		renderErr = progress(result.Rows)
	}
	cancelRender()
	<-heartbeatDone
	heartbeatMu.Lock()
	if renderErr == nil {
		renderErr = heartbeatErr
	}
	heartbeatMu.Unlock()
	if renderErr != nil {
		status := "failed"
		if errors.Is(renderErr, context.Canceled) {
			status = "cancelled"
		}
		_ = w.Store.FinishExportJob(context.WithoutCancel(ctx), job.ID, w.WorkerID, status, renderErr.Error())
		return renderErr
	}
	if err = file.Sync(); err != nil {
		return fail(err)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return fail(err)
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	result.Filename = path.Base(result.Filename)
	objectKey := path.Join("exports", job.DeviceID.String(), job.ID.String(), result.Filename)
	if err = w.Archive.Put(ctx, objectKey, file, size, result.ContentType); err != nil {
		cleanupErr := w.Archive.DeleteObject(context.WithoutCancel(ctx), objectKey)
		if cleanupErr != nil {
			_ = w.Store.FinishExportJobWithArtifact(
				context.WithoutCancel(ctx), job.ID, w.WorkerID, "failed",
				err.Error()+"; artifact cleanup pending: "+cleanupErr.Error(), objectKey,
			)
			return err
		}
		return fail(err)
	}
	err = w.Store.CompleteExportJob(ctx, job.ID, w.WorkerID, result.Format,
		result.Filename, result.ContentType, objectKey, hex.EncodeToString(hash.Sum(nil)),
		size, result.Rows)
	if err != nil {
		cleanupErr := w.Archive.DeleteObject(context.WithoutCancel(ctx), objectKey)
		if cleanupErr != nil {
			_ = w.Store.FinishExportJobWithArtifact(
				context.WithoutCancel(ctx), job.ID, w.WorkerID, "cancelled",
				err.Error()+"; artifact cleanup pending: "+cleanupErr.Error(), objectKey,
			)
		} else {
			_ = w.Store.FinishExportJob(
				context.WithoutCancel(ctx), job.ID, w.WorkerID, "cancelled", err.Error(),
			)
		}
	}
	if err == nil {
		slog.Info("async export completed", "job", job.ID, "device", job.DeviceID,
			"dataset", job.Dataset, "duration", time.Since(started),
			"rows", result.Rows, "bytes", size)
	}
	return err
}

func (w *Worker) expire(ctx context.Context) error {
	items, err := w.Store.ExpireExportJobs(ctx, 100)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.ObjectKey != "" {
			if err = w.Archive.DeleteObject(ctx, item.ObjectKey); err != nil {
				return err
			}
		}
		if err = w.Store.MarkExportExpired(ctx, item.ID); err != nil {
			return err
		}
	}
	return nil
}
