package ingest

import (
	"context"
	"log/slog"
	"time"

	"collector/internal/analytics"

	"github.com/google/uuid"
)

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
	devices := make(map[uuid.UUID]struct{})
	for ctx.Err() == nil {
		rows, err := client.NextSyslogReplayBatch(ctx, analytics.SyslogParserVersion, 500)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			for deviceID := range devices {
				if err := client.ReconcileDevice(ctx, deviceID, time.Time{}); err != nil {
					return err
				}
			}
			slog.Info("historical Syslog reprocess completed",
				"parser_version", analytics.SyslogParserVersion, "events", processed)
			return nil
		}
		completed := make([]uuid.UUID, 0, len(rows))
		events := make([]analytics.SyslogEvent, 0, len(rows))
		for _, row := range rows {
			devices[row.DeviceID] = struct{}{}
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
