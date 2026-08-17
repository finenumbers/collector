package syslogarchive

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"collector/internal/analytics"
	"collector/internal/ftpclient"
	"collector/internal/runtimesettings"
	"collector/internal/store"

	"github.com/google/uuid"
)

type SettingsFunc func() runtimesettings.SyslogArchiveSettings

const maxArchiveBuildsPerTick = 4

var errArchiveAbandoned = errors.New("archive job abandoned")

type Worker struct {
	Store     *store.Store
	Analytics *analytics.Client
	Settings  SettingsFunc
	WorkerID  string
	Poll      time.Duration
	Lease     time.Duration

	historicalPurgeDone bool
	ttlApplied          bool
}

func (w *Worker) Run(ctx context.Context) error {
	if w.Poll <= 0 {
		w.Poll = time.Minute
	}
	if w.Lease <= 0 {
		w.Lease = store.DefaultSyslogArchiveLease
	}
	if w.WorkerID == "" {
		w.WorkerID = fmt.Sprintf("syslog-archive-%d", os.Getpid())
	}
	slog.Info("syslog archive worker started", "worker", w.WorkerID, "poll", w.Poll)
	if w.Store != nil {
		_ = w.Store.TouchSyslogArchiveWorker(ctx, w.WorkerID)
	}
	go w.livenessLoop(ctx)
	ticker := time.NewTicker(w.Poll)
	defer ticker.Stop()
	w.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			w.tick(ctx)
		}
	}
}

func (w *Worker) livenessLoop(ctx context.Context) {
	if w.Store == nil {
		return
	}
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.Store.TouchSyslogArchiveWorker(ctx, w.WorkerID); err != nil {
				slog.Warn("syslog archive worker heartbeat", "error", err)
			}
		}
	}
}

func (w *Worker) tick(ctx context.Context) {
	tickErr := ""
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Error("syslog archive tick panic", "panic", recovered)
			tickErr = fmt.Sprintf("panic: %v", recovered)
		}
		if w.Store != nil {
			_ = w.Store.NoteSyslogArchiveWorkerTick(ctx, w.WorkerID, tickErr)
		}
	}()
	w.applyBufferTTL(ctx)
	w.historicalPurge(ctx)
	w.gcRawHours(ctx)

	cfg := w.settings()
	if !cfg.Enabled {
		return
	}
	if err := os.MkdirAll(cfg.LocalSpoolDir, 0o755); err != nil {
		slog.Error("syslog archive spool mkdir", "error", err)
		tickErr = err.Error()
		return
	}
	w.gcOrphans(cfg.LocalSpoolDir)
	w.enqueueClosedSlots(ctx, cfg)
	builds := 0
	for {
		allowBuild := builds < maxArchiveBuildsPerTick
		worked, built, err := w.processOne(ctx, cfg, allowBuild)
		if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, errArchiveAbandoned) {
			slog.Error("syslog archive job failed", "error", err)
			tickErr = err.Error()
		}
		if built {
			builds++
		}
		if !worked {
			return
		}
		cfg = w.settings()
		if !cfg.Enabled {
			return
		}
	}
}

func (w *Worker) settings() runtimesettings.SyslogArchiveSettings {
	if w.Settings == nil {
		return runtimesettings.Defaults().SyslogArchive
	}
	cfg := w.Settings()
	doc := runtimesettings.Document{SyslogArchive: cfg}
	runtimesettings.NormalizeSyslogArchive(&doc)
	return doc.SyslogArchive
}

func (w *Worker) enqueueClosedSlots(ctx context.Context, cfg runtimesettings.SyslogArchiveSettings) {
	release, ok, err := w.Store.TrySyslogArchiveOrchestratorLock(ctx)
	if err != nil {
		slog.Error("syslog archive orchestrator lock", "error", err)
		return
	}
	if !ok {
		return
	}
	defer release()

	closeDelay, err := time.ParseDuration(cfg.CloseDelay)
	if err != nil {
		closeDelay = time.Minute
	}
	devices, err := w.Store.ListSyslogArchiveDevices(ctx)
	if err != nil {
		slog.Error("list syslog archive devices", "error", err)
		return
	}
	now := time.Now()
	for _, device := range devices {
		if !device.Capabilities.Syslog {
			continue
		}
		if strings.TrimSpace(device.SyslogArchiveRemoteDir) == "" {
			continue
		}
		loc, err := time.LoadLocation(device.ActiveTimezone)
		if err != nil {
			slog.Warn("syslog archive bad timezone", "device", device.ID, "tz", device.ActiveTimezone)
			continue
		}
		closed := ClosedSlotStart(now, loc, closeDelay)
		oldest := closed.Add(-time.Duration(cfg.LookbackHours) * time.Hour)
		hourCounts := map[time.Time]int64{}
		hourCount := func(hour time.Time) int64 {
			hour = hour.UTC().Truncate(time.Hour)
			if count, ok := hourCounts[hour]; ok {
				return count
			}
			fp, fpErr := w.Analytics.SyslogSlotFingerprint(ctx, device.ID, hour, hour.Add(time.Hour))
			if fpErr != nil {
				slog.Error("syslog archive hour fingerprint", "device", device.ID, "hour", hour, "error", fpErr)
				hourCounts[hour] = -1
				return -1
			}
			hourCounts[hour] = fp.Count
			return fp.Count
		}
		for slot := closed; !slot.Before(oldest); slot = slot.Add(-SlotDuration) {
			from, to := SlotBoundsUTC(slot)
			startHour := from.Truncate(time.Hour)
			endHour := to.Add(-time.Nanosecond).Truncate(time.Hour)
			if HourMayDelete(now, startHour) && HourMayDelete(now, endHour) {
				startCount, endCount := hourCount(startHour), hourCount(endHour)
				if startCount == 0 && endCount == 0 {
					continue
				}
			}
			blocked, blockErr := w.slotUTCHoursBlocked(ctx, device.ID, from, to)
			if blockErr != nil {
				slog.Error("syslog archive hour blocked", "device", device.ID, "slot", slot, "error", blockErr)
			} else if blocked {
				continue
			}
			name, nameErr := ArchiveName(device.DeviceSign, slot, loc)
			if nameErr != nil {
				slog.Warn("syslog archive skip device",
					"device", device.ID, "name", device.Name, "reason", "emptySign")
				break
			}
			if _, err := w.Store.EnsureSyslogArchiveJob(
				ctx, device.ID, slot, name, device.SyslogArchiveRemoteDir, device.ActiveTimezone,
			); err != nil && !errors.Is(err, store.ErrNotFound) {
				slog.Error("ensure syslog archive job", "device", device.ID, "slot", slot, "error", err)
			}
		}
		stale := oldest.Add(-SlotDuration)
		if name, nameErr := ArchiveName(device.DeviceSign, stale, loc); nameErr == nil {
			_ = w.Store.EnsureSyslogArchiveSkippedStale(
				ctx, device.ID, stale, name, device.SyslogArchiveRemoteDir, device.ActiveTimezone,
			)
		}
	}
}

func (w *Worker) processOne(
	ctx context.Context, cfg runtimesettings.SyslogArchiveSettings, allowBuild bool,
) (bool, bool, error) {
	job, err := w.Store.ClaimSyslogArchiveJob(ctx, w.WorkerID, w.Lease, allowBuild)
	if errors.Is(err, store.ErrNotFound) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	built := job.Status == store.SyslogArchiveStatusBuilding
	start := time.Now()
	switch job.Status {
	case store.SyslogArchiveStatusBuilding:
		err = w.build(ctx, cfg, job)
	case store.SyslogArchiveStatusUploading:
		err = w.upload(ctx, cfg, job)
	default:
		err = fmt.Errorf("unexpected claimed status %s", job.Status)
	}
	if err != nil {
		if errors.Is(err, errArchiveAbandoned) {
			slog.Info("syslog archive job abandoned",
				"job", job.ID, "device", job.DeviceID, "hour", job.HourStart, "reason", err)
			return true, false, nil
		}
		retry := uploadBackoff(job.Attempts)
		keepLocal := job.LocalPath != ""
		if markErr := w.Store.FailSyslogArchiveJob(ctx, job.ID, w.WorkerID, err.Error(), retry, keepLocal); markErr != nil {
			slog.Error("mark syslog archive failed", "job", job.ID, "error", markErr)
		}
		slog.Error("syslog archive job error",
			"job", job.ID, "device", job.DeviceID, "hour", job.HourStart,
			"phase", job.Status, "attempts", job.Attempts, "error", err,
			"duration", time.Since(start))
		return true, built, err
	}
	slog.Info("syslog archive job ok",
		"job", job.ID, "device", job.DeviceID, "hour", job.HourStart,
		"phase", job.Status, "bytes", job.Bytes, "duration", time.Since(start))
	return true, built, nil
}

func (w *Worker) build(ctx context.Context, cfg runtimesettings.SyslogArchiveSettings, job store.SyslogArchiveJob) error {
	if job.ArchiveName == "" {
		return w.abandon(ctx, job, "missing archive name")
	}
	used, err := w.Store.SyslogArchiveSpoolBytes(ctx)
	if err != nil {
		return err
	}
	if used >= cfg.SpoolBudgetBytes {
		return fmt.Errorf("spool budget exceeded (%d >= %d)", used, cfg.SpoolBudgetBytes)
	}
	if err := os.MkdirAll(cfg.LocalSpoolDir, 0o755); err != nil {
		return err
	}
	loc, err := time.LoadLocation(job.Timezone)
	if err != nil {
		loc = time.UTC
	}
	slotLocal := job.HourStart.In(loc)
	from, to := SlotBoundsUTC(slotLocal)
	blocked, blockErr := w.slotUTCHoursBlocked(ctx, job.DeviceID, from, to)
	if blockErr != nil {
		return blockErr
	}
	if blocked {
		return w.abandon(ctx, job, "utc hour sealed")
	}

	tmp, err := os.CreateTemp(cfg.LocalSpoolDir, "building-*.zip")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	zw := zip.NewWriter(tmp)
	logName := strings.TrimSuffix(job.ArchiveName, ".zip") + ".log"
	entry, err := zw.Create(logName)
	if err != nil {
		return err
	}
	limited := &limitedWriter{w: entry, max: cfg.MaxArchiveBytes}

	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go w.heartbeatLoop(hbCtx, job.ID)

	releaseHeavy, err := w.Store.AcquireClickHouseHeavyLane(ctx)
	if err != nil {
		return err
	}
	_, err = w.Analytics.ExportSyslogPayloadsRaw(ctx, job.DeviceID, from, to, limited)
	releaseHeavy()
	if err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	info, err := os.Stat(tmpPath)
	if err != nil {
		return err
	}
	fp, err := w.Analytics.SyslogSlotFingerprint(ctx, job.DeviceID, from, to)
	if err != nil {
		return err
	}
	count, maxAt, maxID := fingerprintArgs(fp)
	finalPath := filepath.Join(cfg.LocalSpoolDir, job.ID.String()+"_"+job.ArchiveName)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	tmpPath = "" // renamed; skip defer remove of final
	if err := w.Store.MarkSyslogArchiveReady(
		ctx, job.ID, w.WorkerID, finalPath, info.Size(), count, maxAt, maxID,
	); err != nil {
		_ = os.Remove(finalPath)
		return err
	}
	job.LocalPath = finalPath
	job.Bytes = info.Size()
	// Immediately try upload in same tick via re-claim path: mark ready returns;
	// next processOne will pick uploading. Optionally upload now:
	job.Status = store.SyslogArchiveStatusReady
	return w.uploadReady(ctx, cfg, job)
}

func (w *Worker) upload(ctx context.Context, cfg runtimesettings.SyslogArchiveSettings, job store.SyslogArchiveJob) error {
	return w.uploadReady(ctx, cfg, job)
}

func (w *Worker) uploadReady(ctx context.Context, cfg runtimesettings.SyslogArchiveSettings, job store.SyslogArchiveJob) error {
	if job.LocalPath == "" {
		// reclaim after crash mid-upload without path — rebuild if still pending path lost
		return fmt.Errorf("local archive missing")
	}
	info, err := os.Stat(job.LocalPath)
	if err != nil {
		return fmt.Errorf("local archive missing: %w", err)
	}
	if job.Bytes == 0 {
		job.Bytes = info.Size()
	}
	client := ftpclient.New(ftpclient.Config{
		Host: cfg.FTPHost, Port: cfg.FTPPort, User: cfg.FTPUser,
		Password: cfg.FTPPassword, TLS: cfg.FTPTLS,
	})
	if !client.Configured() {
		return errors.New("ftp not configured")
	}

	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go w.heartbeatLoop(hbCtx, job.ID)

	uploadCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	if job.Status != store.SyslogArchiveStatusUploading {
		if err := w.Store.PromoteSyslogArchiveUploading(ctx, job.ID, w.WorkerID, w.Lease); err != nil {
			return err
		}
		job.Status = store.SyslogArchiveStatusUploading
	}

	if ok, _ := client.RemoteMatches(uploadCtx, job.RemoteDir, job.ArchiveName, job.Bytes); ok {
		if err := w.Store.MarkSyslogArchiveUploaded(ctx, job.ID, w.WorkerID); err != nil {
			return err
		}
		_ = os.Remove(job.LocalPath)
		return nil
	}

	file, err := os.Open(job.LocalPath)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := client.UploadAtomic(uploadCtx, job.RemoteDir, job.ArchiveName, file, job.Bytes); err != nil {
		return err
	}
	if err := w.Store.MarkSyslogArchiveUploaded(ctx, job.ID, w.WorkerID); err != nil {
		return err
	}
	_ = os.Remove(job.LocalPath)
	return nil
}

func (w *Worker) slotUTCHoursBlocked(
	ctx context.Context, deviceID uuid.UUID, from, to time.Time,
) (bool, error) {
	hours := []time.Time{from.Truncate(time.Hour), to.Add(-time.Nanosecond).Truncate(time.Hour)}
	seen := map[time.Time]struct{}{}
	for _, hour := range hours {
		if _, ok := seen[hour]; ok {
			continue
		}
		seen[hour] = struct{}{}
		blocked, err := w.Store.SyslogUTCHourBlocked(ctx, deviceID, hour)
		if err != nil {
			return false, err
		}
		if blocked {
			return true, nil
		}
	}
	return false, nil
}

func (w *Worker) abandon(ctx context.Context, job store.SyslogArchiveJob, msg string) error {
	if err := w.Store.AbandonSyslogArchiveJob(ctx, job.ID, w.WorkerID, msg); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", errArchiveAbandoned, msg)
}

// HideWorkerLastError reports whether a worker last_error is an operational
// abandon (sealed/purged hour), not an FTP or build failure for the status line.
func HideWorkerLastError(msg string) bool {
	return strings.Contains(strings.ToLower(msg), "utc hour sealed")
}

func (w *Worker) heartbeatLoop(ctx context.Context, jobID uuid.UUID) {
	ticker := time.NewTicker(w.Lease / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.Store.HeartbeatSyslogArchiveJob(ctx, jobID, w.WorkerID, w.Lease)
			_ = w.Store.TouchSyslogArchiveWorker(ctx, w.WorkerID)
		}
	}
}

func (w *Worker) gcOrphans(spoolDir string) {
	entries, err := os.ReadDir(spoolDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "building-") || strings.HasSuffix(name, ".part") {
			path := filepath.Join(spoolDir, name)
			info, err := entry.Info()
			if err == nil && time.Since(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			}
		}
	}
}

func uploadBackoff(attempts int) time.Duration {
	switch {
	case attempts <= 1:
		return time.Minute
	case attempts == 2:
		return 5 * time.Minute
	case attempts == 3:
		return 15 * time.Minute
	default:
		return 30 * time.Minute
	}
}

type limitedWriter struct {
	w       io.Writer
	written int64
	max     int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.max > 0 && l.written+int64(len(p)) > l.max {
		return 0, fmt.Errorf("archive exceeds maxArchiveBytes (%d)", l.max)
	}
	n, err := l.w.Write(p)
	l.written += int64(n)
	return n, err
}

func fingerprintArgs(fp analytics.SyslogSlotFingerprint) (int64, *time.Time, *uuid.UUID) {
	if fp.Count == 0 {
		return 0, nil, nil
	}
	ts := fp.MaxReceivedAt.UTC()
	id := fp.MaxEventID
	return fp.Count, &ts, &id
}
