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
	syslogConstructsEnabled ...bool,
) error {
	if err := ensureDeviceRevisionJobs(ctx, client, control); err != nil {
		return err
	}
	continuations := NewContinuationAssembler()
	constructsEnabled := len(syslogConstructsEnabled) > 0 && syslogConstructsEnabled[0]
	var constructs *SyslogConstructAssembler
	if constructsEnabled {
		constructs = NewSyslogConstructAssembler()
	}
	lastBootstrap := time.Now()
	for ctx.Err() == nil {
		if time.Since(lastBootstrap) >= 30*time.Second {
			if err := ensureDeviceRevisionJobs(ctx, client, control); err != nil {
				return err
			}
			lastBootstrap = time.Now()
		}
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
			if err := processDeviceRevisionJob(
				ctx, client, control, continuations, constructs, constructsEnabled, initial,
			); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
}

func processDeviceRevisionJob(
	ctx context.Context, client *analytics.Client, control *store.Store,
	continuations *ContinuationAssembler, constructs *SyslogConstructAssembler,
	constructsEnabled bool,
	job analytics.DeviceRevisionJob,
) error {
	release := control.LockDeviceWrites(job.DeviceID)
	defer release()
	config, err := control.DeviceTimeConfig(ctx, job.DeviceID)
	if errors.Is(err, store.ErrDeviceDeleting) || errors.Is(err, store.ErrNotFound) {
		return client.SupersedeDeviceRevision(ctx, job, "device is being deleted")
	}
	if err != nil {
		return err
	}
	if uint64(config.TimezoneRevision) != job.Revision {
		return client.SupersedeDeviceRevision(ctx, job, "newer device timezone revision exists")
	}
	rows, err := client.NextDeviceRevisionSyslogBatch(ctx, job, 1_000)
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		location, err := time.LoadLocation(job.Timezone)
		if err != nil {
			return err
		}
		events := make([]analytics.SyslogEvent, 0, len(rows))
		for _, row := range rows {
			events = append(events, ParseSyslogInLocation(RawSyslog{
				EventID: row.EventID, DeviceID: row.DeviceID,
				ReceivedAt: row.ReceivedAt, SourceIP: row.SourceIP.String(),
				SourcePort: row.SourcePort, Payload: row.Payload,
				Timezone: job.Timezone, TimezoneRevision: job.Revision,
			}, location))
		}
		continuations.Assemble(events)
		if err := client.InsertSyslogFactsBatch(ctx, events); err != nil {
			return err
		}
		if constructsEnabled {
			constructRows, memberRows, fragmentLinks := constructs.Assemble(events)
			if err := client.InsertSyslogFragmentLinksBatch(ctx, fragmentLinks); err != nil {
				return err
			}
			if err := client.InsertSyslogConstructsBatch(ctx, constructRows); err != nil {
				return err
			}
			if err := client.InsertSyslogConstructMembersBatch(ctx, memberRows); err != nil {
				return err
			}
		}
		if err := client.ProcessSyslogShadowDerivedBatch(ctx, events); err != nil {
			return err
		}
		return client.AdvanceDeviceRevisionSyslog(ctx, job, rows)
	}
	var cdrDone bool
	job, cdrDone, err = client.RebuildCDRTimeChunk(ctx, job, 1_000)
	if err != nil || !cdrDone {
		return err
	}
	if job.Status == "building" {
		if err := control.ActivateDeviceTimezoneRevision(ctx, job.DeviceID, int64(job.Revision)); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return client.SupersedeDeviceRevision(
					ctx, job, "newer device timezone revision exists",
				)
			}
			return err
		}
		return client.BeginDeviceRevisionCutover(ctx, job)
	}
	if job.CutoverSealed == 0 {
		if time.Since(job.UpdatedAt) < 6*time.Second {
			return nil
		}
		_, _, err = client.RefreshDeviceRevisionHighWatermarks(ctx, job)
		return err
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
	return nil
}

func ensureDeviceRevisionJobs(
	ctx context.Context, client *analytics.Client, control *store.Store,
) error {
	devices, err := control.ListDevices(ctx)
	if err != nil {
		return err
	}
	for _, device := range devices {
		if !device.Enabled {
			continue
		}
		activeRevision, err := client.ActiveDeviceRevision(ctx, device.ID)
		if err != nil {
			return err
		}
		if device.TimezoneRevision == device.ActiveTimezoneRevision &&
			activeRevision == uint64(device.ActiveTimezoneRevision) {
			continue
		}
		if err := client.ScheduleDeviceRebuild(
			ctx, device.ID, uint64(device.TimezoneRevision), device.Timezone,
		); err != nil {
			return err
		}
	}
	return nil
}

type DeviceTimezoneResolver interface {
	DeviceTimezone(context.Context, uuid.UUID) (string, error)
}

type deviceTimeConfigResolver interface {
	DeviceTimeConfig(context.Context, uuid.UUID) (store.DeviceTimeConfig, error)
}

type deviceReprocessConfig struct {
	timezone string
	revision uint64
	skip     bool
}

func RunHistoricalSyslogReprocess(
	ctx context.Context, client *analytics.Client, resolver DeviceTimezoneResolver,
	syslogConstructsEnabled ...bool,
) error {
	for ctx.Err() == nil {
		if err := RunHistoricalSyslogReprocessOnce(ctx, client, resolver, syslogConstructsEnabled...); err != nil {
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
	syslogConstructsEnabled ...bool,
) error {
	var processed uint64
	configs := make(map[uuid.UUID]deviceReprocessConfig)
	continuations := NewContinuationAssembler()
	constructsEnabled := len(syslogConstructsEnabled) > 0 && syslogConstructsEnabled[0]
	var constructs *SyslogConstructAssembler
	if constructsEnabled {
		constructs = NewSyslogConstructAssembler()
	}
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
		events := make([]analytics.SyslogEvent, 0, len(rows))
		skipped := make([]analytics.SyslogEvent, 0)
		for _, row := range rows {
			config, resolveErr := resolveDeviceReprocessConfig(ctx, resolver, configs, row)
			if resolveErr != nil {
				return resolveErr
			}
			if config.skip {
				skipped = append(skipped, analytics.SyslogEvent{
					EventID: row.EventID, DeviceID: row.DeviceID,
				})
				continue
			}
			location, locationErr := time.LoadLocation(config.timezone)
			if locationErr != nil {
				return locationErr
			}
			event := ParseSyslogInLocation(RawSyslog{
				EventID: row.EventID, DeviceID: row.DeviceID, ReceivedAt: row.ReceivedAt,
				SourceIP: row.SourceIP.String(), SourcePort: row.SourcePort, Payload: row.Payload,
				Timezone: config.timezone, TimezoneRevision: config.revision,
			}, location)
			events = append(events, event)
		}
		continuations.Assemble(events)
		for _, event := range events {
			if err := client.ProcessSyslogDerived(ctx, event); err != nil {
				return err
			}
		}
		if err := client.InsertSyslogInterpretationsBatch(ctx, events); err != nil {
			return err
		}
		if constructsEnabled {
			constructRows, memberRows, fragmentLinks := constructs.Assemble(events)
			if err := client.InsertSyslogFragmentLinksBatch(ctx, fragmentLinks); err != nil {
				return err
			}
			if err := client.InsertSyslogConstructsBatch(ctx, constructRows); err != nil {
				return err
			}
			if err := client.InsertSyslogConstructMembersBatch(ctx, memberRows); err != nil {
				return err
			}
		}
		ledger := append(events, skipped...)
		if err := client.MarkSyslogReprocessedBatch(
			ctx, ledger, analytics.SyslogParserVersion,
		); err != nil {
			return err
		}
		processed += uint64(len(ledger))
		if processed%5000 == 0 {
			slog.Info("historical Syslog reprocess progress",
				"parser_version", analytics.SyslogParserVersion, "events", processed)
		}
	}
	return ctx.Err()
}

func resolveDeviceReprocessConfig(
	ctx context.Context,
	resolver DeviceTimezoneResolver,
	cache map[uuid.UUID]deviceReprocessConfig,
	row analytics.ReplaySyslogRow,
) (deviceReprocessConfig, error) {
	if cached, ok := cache[row.DeviceID]; ok {
		return cached, nil
	}
	config := deviceReprocessConfig{timezone: row.SourceTimezone, revision: 1}
	if config.timezone == "" {
		config.timezone = "UTC"
	}
	if configResolver, ok := resolver.(deviceTimeConfigResolver); ok {
		deviceConfig, err := configResolver.DeviceTimeConfig(ctx, row.DeviceID)
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrDeviceDeleting) {
			config.skip = true
			cache[row.DeviceID] = config
			return config, nil
		}
		if err != nil {
			return deviceReprocessConfig{}, err
		}
		config.timezone = deviceConfig.ActiveTimezone
		if config.timezone == "" {
			config.timezone = deviceConfig.Timezone
		}
		if config.timezone == "" {
			config.timezone = "UTC"
		}
		if deviceConfig.ActiveTimezoneRevision > 0 {
			config.revision = uint64(deviceConfig.ActiveTimezoneRevision)
		} else if deviceConfig.TimezoneRevision > 0 {
			config.revision = uint64(deviceConfig.TimezoneRevision)
		}
		cache[row.DeviceID] = config
		return config, nil
	}
	if resolver != nil {
		resolved, err := resolver.DeviceTimezone(ctx, row.DeviceID)
		if errors.Is(err, store.ErrNotFound) {
			config.skip = true
			cache[row.DeviceID] = config
			return config, nil
		}
		if err != nil {
			return deviceReprocessConfig{}, err
		}
		if resolved != "" {
			config.timezone = resolved
		}
	}
	cache[row.DeviceID] = config
	return config, nil
}
