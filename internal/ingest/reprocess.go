package ingest

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"collector/internal/analytics"
	"collector/internal/equipment"
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
				TemplateKey: config.TemplateKey, Firmware: config.Firmware,
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
		if !device.Enabled ||
			(!device.Capabilities.Syslog && !device.Capabilities.TypedCDR) {
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
	template string
	firmware string
	skip     bool
}

func RunHistoricalSyslogReprocess(
	ctx context.Context, client *analytics.Client, resolver DeviceTimezoneResolver,
	syslogConstructsEnabled ...bool,
) error {
	constructsEnabled := len(syslogConstructsEnabled) > 0 && syslogConstructsEnabled[0]
	return RunHistoricalSyslogReprocessWithOptions(
		ctx, client, resolver, constructsEnabled, SyslogReplayOptions{},
	)
}

type SyslogReplayOptions struct {
	Paused         bool
	BatchSize      uint64
	Sleep          time.Duration
	MaxThreads     int
	MaxMemoryUsage uint64
}

func (options SyslogReplayOptions) withDefaults() SyslogReplayOptions {
	if options.BatchSize == 0 {
		options.BatchSize = 500
	}
	if options.Sleep == 0 {
		options.Sleep = 250 * time.Millisecond
	}
	if options.MaxThreads <= 0 {
		options.MaxThreads = 2
	}
	if options.MaxMemoryUsage == 0 {
		options.MaxMemoryUsage = 512 << 20
	}
	return options
}

func RunHistoricalSyslogReprocessWithOptions(
	ctx context.Context,
	client *analytics.Client,
	resolver DeviceTimezoneResolver,
	syslogConstructsEnabled bool,
	options SyslogReplayOptions,
) error {
	options = options.withDefaults()
	for ctx.Err() == nil {
		if err := RunHistoricalSyslogReprocessOnceWithOptions(
			ctx, client, resolver, syslogConstructsEnabled, options,
		); err != nil {
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
	constructsEnabled := len(syslogConstructsEnabled) > 0 && syslogConstructsEnabled[0]
	return RunHistoricalSyslogReprocessOnceWithOptions(
		ctx, client, resolver, constructsEnabled, SyslogReplayOptions{},
	)
}

func RunHistoricalSyslogReprocessOnceWithOptions(
	ctx context.Context,
	client *analytics.Client,
	resolver DeviceTimezoneResolver,
	constructsEnabled bool,
	options SyslogReplayOptions,
) error {
	control, ok := resolver.(*store.Store)
	if !ok {
		return errors.New("durable Syslog replay requires a PostgreSQL store")
	}
	options = options.withDefaults()
	if err := ensureSyslogParserRebuildJobs(ctx, client, control, options); err != nil {
		return err
	}
	if err := control.SetSyslogParserRebuildPaused(
		ctx, analytics.SyslogParserVersion, options.Paused,
	); err != nil {
		return err
	}
	if options.Paused {
		slog.Warn("historical Syslog replay is paused",
			"parser_version", analytics.SyslogParserVersion)
		return nil
	}

	configs := make(map[uuid.UUID]deviceReprocessConfig)
	continuations := make(map[uuid.UUID]*ContinuationAssembler)
	constructs := make(map[uuid.UUID]*SyslogConstructAssembler)
	for ctx.Err() == nil {
		job, err := control.ClaimSyslogParserRebuildJob(
			ctx, analytics.SyslogParserVersion, 5*time.Minute,
		)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if continuations[job.DeviceID] == nil {
			continuations[job.DeviceID] = NewContinuationAssembler()
		}
		if constructsEnabled && constructs[job.DeviceID] == nil {
			constructs[job.DeviceID] = NewSyslogConstructAssembler()
		}
		release := control.LockDeviceWrites(job.DeviceID)
		batchEvents, processErr := processSyslogParserRebuildBatch(
			ctx, client, control, resolver, configs, continuations[job.DeviceID],
			constructs[job.DeviceID], constructsEnabled, job, options,
		)
		release()
		if processErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if retryErr := control.RetrySyslogParserRebuildJob(
				ctx, job, processErr, 30*time.Second,
			); retryErr != nil {
				return errors.Join(processErr, retryErr)
			}
			slog.Error("historical Syslog replay batch failed",
				"device", job.DeviceID, "parser_version", job.ParserVersion,
				"attempt", job.Attempts, "error", processErr)
			continue
		}
		if batchEvents == 0 {
			slog.Info("historical Syslog replay device completed",
				"device", job.DeviceID, "parser_version", job.ParserVersion,
				"events", job.TotalEvents, "batches", job.ProcessedBatches)
		}
		if options.Sleep > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(options.Sleep):
			}
		}
	}
	return ctx.Err()
}

func ensureSyslogParserRebuildJobs(
	ctx context.Context,
	client *analytics.Client,
	control *store.Store,
	options SyslogReplayOptions,
) error {
	devices, err := control.ListDevicesByCategory(ctx, equipment.CategoryEquipment)
	if err != nil {
		return err
	}
	queryOptions := analytics.SyslogReplayQueryOptions{
		MaxThreads: options.MaxThreads, MaxMemoryUsage: options.MaxMemoryUsage,
		QueryLabel: "syslog-replay-watermark",
	}
	for _, device := range devices {
		if !device.Enabled || device.PurgeState != "active" || !device.Capabilities.Syslog {
			continue
		}
		exists, err := control.HasSyslogParserRebuildJob(
			ctx, device.ID, analytics.SyslogParserVersion,
		)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		watermark, err := client.DeviceSyslogReplayWatermark(ctx, device.ID, queryOptions)
		if err != nil {
			return err
		}
		if err := control.EnsureSyslogParserRebuildJob(
			ctx, device.ID, analytics.SyslogParserVersion, watermark.ReceivedAtUS,
			watermark.EventID, watermark.TotalEvents,
		); err != nil {
			return err
		}
	}
	return nil
}

func processSyslogParserRebuildBatch(
	ctx context.Context,
	client *analytics.Client,
	control *store.Store,
	resolver DeviceTimezoneResolver,
	configs map[uuid.UUID]deviceReprocessConfig,
	continuations *ContinuationAssembler,
	constructs *SyslogConstructAssembler,
	constructsEnabled bool,
	job store.SyslogParserRebuildJob,
	options SyslogReplayOptions,
) (uint64, error) {
	queryOptions := analytics.SyslogReplayQueryOptions{
		MaxThreads: options.MaxThreads, MaxMemoryUsage: options.MaxMemoryUsage,
		QueryLabel: "syslog-parser-rebuild",
	}
	rows, err := client.NextDeviceSyslogReplayBatch(
		ctx, job.DeviceID, job.CursorReceivedUS, job.CursorEventID,
		job.WatermarkReceivedUS, job.WatermarkEventID, options.BatchSize, queryOptions,
	)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, control.CompleteSyslogParserRebuildJob(ctx, job)
	}
	events := make([]analytics.SyslogEvent, 0, len(rows))
	skipped := make([]analytics.SyslogEvent, 0)
	for _, row := range rows {
		config, resolveErr := resolveDeviceReprocessConfig(ctx, resolver, configs, row)
		if resolveErr != nil {
			return 0, resolveErr
		}
		if config.skip {
			skipped = append(skipped, analytics.SyslogEvent{
				EventID: row.EventID, DeviceID: row.DeviceID,
			})
			continue
		}
		location, locationErr := time.LoadLocation(config.timezone)
		if locationErr != nil {
			return 0, locationErr
		}
		events = append(events, ParseSyslogInLocation(RawSyslog{
			EventID: row.EventID, DeviceID: row.DeviceID, ReceivedAt: row.ReceivedAt,
			SourceIP: row.SourceIP.String(), SourcePort: row.SourcePort, Payload: row.Payload,
			Timezone: config.timezone, TimezoneRevision: config.revision,
			TemplateKey: config.template, Firmware: config.firmware,
		}, location))
	}
	continuations.Assemble(events)
	if err := client.InsertSyslogInterpretationsBatch(ctx, events); err != nil {
		return 0, err
	}
	if err := client.ProcessSyslogShadowDerivedBatch(ctx, events); err != nil {
		return 0, err
	}
	if err := client.EnqueueDirtySyslogBuckets(ctx, events); err != nil {
		return 0, err
	}
	if constructsEnabled {
		constructRows, memberRows, fragmentLinks := constructs.Assemble(events)
		if err := client.InsertSyslogFragmentLinksBatch(ctx, fragmentLinks); err != nil {
			return 0, err
		}
		if err := client.InsertSyslogConstructsBatch(ctx, constructRows); err != nil {
			return 0, err
		}
		if err := client.InsertSyslogConstructMembersBatch(ctx, memberRows); err != nil {
			return 0, err
		}
	}
	if err := control.HeartbeatSyslogParserRebuildJob(ctx, job); err != nil {
		return 0, err
	}
	ledger := append(events, skipped...)
	if err := client.MarkSyslogReprocessedBatch(ctx, ledger, job.ParserVersion); err != nil {
		return 0, err
	}
	last := rows[len(rows)-1]
	if err := control.AdvanceSyslogParserRebuildJob(
		ctx, job, last.ReceivedAtUS, last.EventID, uint64(len(rows)),
	); err != nil {
		return 0, err
	}
	slog.Info("historical Syslog replay progress",
		"device", job.DeviceID, "parser_version", job.ParserVersion,
		"processed", job.ProcessedEvents+uint64(len(rows)), "total", job.TotalEvents,
		"batch", len(rows))
	return uint64(len(rows)), nil
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
		config.template = deviceConfig.TemplateKey
		config.firmware = deviceConfig.Firmware
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
