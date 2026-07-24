package ingest

import (
	"context"
	"log/slog"

	"collector/internal/analytics"

	"github.com/google/uuid"
)

func RunHistoricalSyslogReprocess(ctx context.Context, client *analytics.Client) error {
	var processed uint64
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
		for _, row := range rows {
			event := ParseSyslog(RawSyslog{
				EventID: row.EventID, DeviceID: row.DeviceID, ReceivedAt: row.ReceivedAt,
				SourceIP: row.SourceIP.String(), SourcePort: row.SourcePort, Payload: row.Payload,
			})
			if err := client.ProcessSyslogDerived(ctx, event); err != nil {
				return err
			}
			completed = append(completed, row.EventID)
		}
		if err := client.MarkSyslogReprocessedBatch(
			ctx, completed, analytics.SyslogParserVersion,
		); err != nil {
			return err
		}
		processed += uint64(len(completed))
		if processed%5000 == 0 {
			slog.Info("historical Syslog reprocess progress",
				"parser_version", analytics.SyslogParserVersion, "events", processed)
		}
	}
	return nil
}
