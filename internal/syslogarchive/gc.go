package syslogarchive

import (
	"context"
	"log/slog"
	"time"

	"collector/internal/store"
)

const rawGCLookback = 24 * time.Hour

func (w *Worker) applyBufferTTL(ctx context.Context) {
	if w.ttlApplied || w.Analytics == nil {
		return
	}
	if err := w.Analytics.ApplySyslogMessagesBufferTTL(ctx); err != nil {
		slog.Warn("syslog_messages buffer TTL", "error", err)
		return
	}
	w.ttlApplied = true
}

func (w *Worker) historicalPurge(ctx context.Context) {
	if w.historicalPurgeDone || w.Analytics == nil {
		return
	}
	cutoff := RawDeleteCutoff(time.Now())
	if err := w.Analytics.DeleteSyslogOlderThan(ctx, cutoff); err != nil {
		slog.Warn("historical syslog purge", "cutoff", cutoff, "error", err)
		return
	}
	if err := w.Store.SetSyslogRawHistoryCutoff(ctx, cutoff); err != nil {
		slog.Warn("historical syslog cutoff", "cutoff", cutoff, "error", err)
		return
	}
	slog.Info("historical syslog purge done", "cutoff", cutoff)
	w.historicalPurgeDone = true
}

func (w *Worker) gcRawHours(ctx context.Context) {
	if w.Store == nil || w.Analytics == nil {
		return
	}
	release, ok, err := w.Store.TrySyslogRawGCLock(ctx)
	if err != nil {
		slog.Error("syslog raw GC lock", "error", err)
		return
	}
	if !ok {
		return
	}
	defer release()

	devices, err := w.Store.ListSyslogCapableDevices(ctx)
	if err != nil {
		slog.Error("list syslog devices for GC", "error", err)
		return
	}
	cfg := w.settings()
	now := time.Now()
	newest := now.UTC().Truncate(time.Hour).Add(-time.Hour)
	oldest := newest.Add(-rawGCLookback)
	for _, device := range devices {
		for hour := newest; !hour.Before(oldest); hour = hour.Add(-time.Hour) {
			if !HourMayDelete(now, hour) {
				continue
			}
			if err := w.gcUTCHour(ctx, cfg.Enabled, device, hour); err != nil {
				slog.Warn("syslog raw GC hour",
					"device", device.ID, "hour", hour, "error", err)
				_ = w.Store.FailSyslogRawGC(ctx, device.ID, hour, err.Error())
			}
		}
	}
}

func (w *Worker) gcUTCHour(
	ctx context.Context, archiveEnabled bool, device store.Device, hour time.Time,
) error {
	done, err := w.Store.SyslogRawAlreadyDeleted(ctx, device.ID, hour)
	if err != nil || done {
		return err
	}
	if !archiveEnabled {
		return nil
	}
	from, to := hour.UTC(), hour.UTC().Add(time.Hour)
	fp, err := w.Analytics.SyslogSlotFingerprint(ctx, device.ID, from, to)
	if err != nil {
		return err
	}
	var pending, archived int
	if device.SyslogArchiveEnabled {
		var countErr error
		pending, archived, countErr = w.Store.ArchiveJobsForUTCHour(ctx, device.ID, hour)
		if countErr != nil {
			return countErr
		}
	}
	completed, afEnabled, err := w.Store.CustomProjectionHourCompleted(ctx, device.ID, hour)
	if err != nil {
		return err
	}
	nextCompleted, _, err := w.Store.CustomProjectionHourCompleted(ctx, device.ID, hour.Add(time.Hour))
	if err != nil {
		return err
	}
	var pendingCoverage uint64
	if afEnabled {
		pendingCoverage, err = w.Analytics.PendingAntiFraudCoverage(ctx, device.ID, from, to)
		if err != nil {
			return err
		}
	}
	if !hourGCGatesReady(
		time.Now(), hour, archiveEnabled, device.SyslogArchiveEnabled,
		fp.Count, pending, archived, completed, nextCompleted, pendingCoverage,
	) {
		return nil
	}
	if device.SyslogArchiveEnabled {
		jobs, listErr := w.Store.ListSyslogArchiveJobsOverlappingUTCHour(ctx, device.ID, hour)
		if listErr != nil {
			return listErr
		}
		for _, job := range jobs {
			if job.Status == store.SyslogArchiveStatusUploaded &&
				job.PayloadCount == 0 && job.MaxEventID == nil {
				continue
			}
			slotFrom, slotTo := SlotBoundsUTC(job.HourStart)
			slotFP, fpErr := w.Analytics.SyslogSlotFingerprint(ctx, device.ID, slotFrom, slotTo)
			if fpErr != nil {
				return fpErr
			}
			count, maxAt, maxID := fingerprintArgs(slotFP)
			changed, requeueErr := w.Store.RequeueSyslogArchiveIfStaleFingerprint(
				ctx, job.ID, count, maxAt, maxID,
			)
			if requeueErr != nil {
				return requeueErr
			}
			if changed {
				return nil
			}
		}
	}
	if err := w.Store.SealSyslogUTCHour(ctx, device.ID, hour); err != nil {
		return err
	}
	if fp.Count > 0 {
		if err := w.Analytics.DeleteSyslogRange(ctx, device.ID, from, to); err != nil {
			return err
		}
	}
	return w.Store.MarkSyslogRawDeleted(ctx, device.ID, hour)
}

func hourGCGatesReady(
	now, hourStart time.Time,
	archiveEnabled, deviceArchiveEnabled bool,
	rawCount int64, pendingJobs, archivedJobs int,
	afHourDone, afNextHourDone bool, pendingCoverage uint64,
) bool {
	if !HourMayDelete(now, hourStart) {
		return false
	}
	if !archiveEnabled {
		return false
	}
	if deviceArchiveEnabled {
		if pendingJobs > 0 {
			return false
		}
		if rawCount > 0 && archivedJobs == 0 {
			return false
		}
	}
	if !afHourDone || !afNextHourDone {
		return false
	}
	if pendingCoverage > 0 {
		return false
	}
	return true
}
