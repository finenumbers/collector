package ingest

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"collector/internal/analytics"
	"collector/internal/store"

	"github.com/google/uuid"
)

func RunDeviceRevisionRebuilds(
	ctx context.Context, client *analytics.Client, control *store.Store,
) error {
	devices, err := control.ListDevices(ctx)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if device.TimezoneRevision == device.ActiveTimezoneRevision {
			continue
		}
		if err := client.ScheduleDeviceRebuild(
			ctx, device.ID, uint64(device.TimezoneRevision), device.Timezone,
		); err != nil {
			return err
		}
	}
	for ctx.Err() == nil {
		jobs, err := client.ListBuildingDeviceRevisions(ctx)
		if err != nil {
			return err
		}
		if len(jobs) == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
				continue
			}
		}
		for _, initial := range jobs {
			job := initial
			config, configErr := control.DeviceTimeConfig(ctx, job.DeviceID)
			if configErr != nil {
				return configErr
			}
			if uint64(config.TimezoneRevision) != job.Revision {
				if err := client.SupersedeDeviceRevision(
					ctx, job, "newer device timezone revision exists",
				); err != nil {
					return err
				}
				continue
			}
			rows, err := client.NextDeviceRevisionSyslogBatch(ctx, job, 1_000)
			if err != nil {
				return err
			}
			if len(rows) != 0 {
				location, locationErr := time.LoadLocation(job.Timezone)
				if locationErr != nil {
					return locationErr
				}
				events := make([]analytics.SyslogEvent, 0, len(rows))
				for _, row := range rows {
					event := ParseSyslogInLocation(RawSyslog{
						EventID: row.EventID, DeviceID: row.DeviceID,
						ReceivedAt: row.ReceivedAt, SourceIP: row.SourceIP.String(),
						SourcePort: row.SourcePort, Payload: row.Payload,
						Timezone: job.Timezone, TimezoneRevision: job.Revision,
					}, location)
					events = append(events, event)
				}
				if err := client.InsertSyslogFactsBatch(ctx, events); err != nil {
					return err
				}
				if err := client.ProcessSyslogShadowDerivedBatch(ctx, events); err != nil {
					return err
				}
				if err := client.AdvanceDeviceRevisionSyslog(ctx, job, rows); err != nil {
					return err
				}
				continue
			}
			var cdrDone bool
			job, cdrDone, err = client.RebuildCDRTimeChunk(ctx, job, 1_000)
			if err != nil {
				return err
			}
			if !cdrDone {
				continue
			}
			if job.Status == "building" {
				if err := control.ActivateDeviceTimezoneRevision(
					ctx, job.DeviceID, int64(job.Revision),
				); err != nil {
					if errors.Is(err, store.ErrNotFound) {
						if supersedeErr := client.SupersedeDeviceRevision(
							ctx, job, "newer device timezone revision exists",
						); supersedeErr != nil {
							return supersedeErr
						}
						continue
					}
					return err
				}
				if err := client.BeginDeviceRevisionCutover(ctx, job); err != nil {
					return err
				}
				continue
			}
			if job.CutoverSealed == 0 {
				if time.Since(job.UpdatedAt) < 6*time.Second {
					continue
				}
				job, _, err = client.RefreshDeviceRevisionHighWatermarks(ctx, job)
				if err != nil {
					return err
				}
				continue
			}
			job, err = client.MarkDeviceRevisionReady(ctx, job)
			if err != nil {
				return err
			}
			if err := client.ActivateDeviceRevision(ctx, job); err != nil {
				return err
			}
			slog.Info("device derived revision activated",
				"device", job.DeviceID, "revision", job.Revision,
				"timezone", job.Timezone, "syslog", job.Processed,
				"cdr", job.CDRProcessed, "antifraud", job.LifecycleCount)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

type DeviceTimezoneResolver interface {
	DeviceTimezone(context.Context, uuid.UUID) (string, error)
}

func RunHistoricalSyslogReprocess(
	ctx context.Context, client *analytics.Client, resolver DeviceTimezoneResolver,
) error {
	for ctx.Err() == nil {
		if err := RunHistoricalSyslogReprocessOnce(ctx, client, resolver); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(30 * time.Second):
		}
	}
	return nil
}

func RunHistoricalSyslogReprocessOnce(
	ctx context.Context, client *analytics.Client, resolver DeviceTimezoneResolver,
) error {
	var processed uint64
	timezones := make(map[uuid.UUID]string)
	for ctx.Err() == nil {
		rows, err := client.NextSyslogReplayBatch(ctx, analytics.SyslogParserVersion, 500)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			slog.Info("historical Syslog reprocess completed",
				"parser_version", analytics.SyslogParserVersion, "events", processed)
			return nil
		}
		completed := make([]uuid.UUID, 0, len(rows))
		events := make([]analytics.SyslogEvent, 0, len(rows))
		for _, row := range rows {
			timezone := row.SourceTimezone
			if resolver != nil {
				if cached, ok := timezones[row.DeviceID]; ok {
					timezone = cached
				} else {
					resolved, resolveErr := resolver.DeviceTimezone(ctx, row.DeviceID)
					if resolveErr != nil {
						return resolveErr
					}
					timezone = resolved
					timezones[row.DeviceID] = timezone
				}
			}
			if timezone == "" {
				timezone = "UTC"
			}
			location, locationErr := time.LoadLocation(timezone)
			if locationErr != nil {
				return locationErr
			}
			event := ParseSyslogInLocation(RawSyslog{
				EventID: row.EventID, DeviceID: row.DeviceID, ReceivedAt: row.ReceivedAt,
				SourceIP: row.SourceIP.String(), SourcePort: row.SourcePort, Payload: row.Payload,
				Timezone: timezone,
			}, location)
			if err := client.ProcessSyslogDerived(ctx, event); err != nil {
				return err
			}
			events = append(events, event)
			completed = append(completed, row.EventID)
		}
		if err := client.InsertSyslogInterpretationsBatch(ctx, events); err != nil {
			return err
		}
		if err := client.MarkSyslogReprocessedBatch(
			ctx, events, analytics.SyslogParserVersion,
		); err != nil {
			return err
		}
		processed += uint64(len(completed))
		if processed%5000 == 0 {
			slog.Info("historical Syslog reprocess progress",
				"parser_version", analytics.SyslogParserVersion, "events", processed)
		}
	}
	return ctx.Err()
}
