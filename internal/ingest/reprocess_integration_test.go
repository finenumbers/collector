package ingest

import (
	"context"
	"os"
	"testing"
	"time"

	"collector/internal/analytics"

	"github.com/google/uuid"
)

type fixedTimezoneResolver string

func (r fixedTimezoneResolver) DeviceTimezone(
	_ context.Context, _ uuid.UUID,
) (string, error) {
	return string(r), nil
}

func TestHistoricalSyslogReprocessIsIdempotent(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	client, err := analytics.Open(
		address, "collector", os.Getenv("CLICKHOUSE_TEST_USER"),
		os.Getenv("CLICKHOUSE_TEST_PASSWORD"),
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse"); err != nil {
		t.Fatal(err)
	}
	deviceID, eventID := uuid.New(), uuid.New()
	event := ParseSyslog(RawSyslog{
		EventID: eventID, DeviceID: deviceID, ReceivedAt: time.Now().UTC(),
		SourceIP: "10.0.0.10", SourcePort: 10003,
		Payload: []byte(`<14> <smg1016m> 17:00:00.1 [INFO] [CREPLAY] RADIUS. ` +
			`Access-Request Acct-Session-Id='replay-session' ` +
			`Cisco-AVPair='xpgk-request-type=check_call'`),
	})
	if err := client.InsertSyslog(ctx, event); err != nil {
		t.Fatal(err)
	}
	resolver := fixedTimezoneResolver("Asia/Novosibirsk")
	if err := RunHistoricalSyslogReprocessOnce(ctx, client, resolver); err != nil {
		t.Fatal(err)
	}
	if err := RunHistoricalSyslogReprocessOnce(ctx, client, resolver); err != nil {
		t.Fatal(err)
	}
	var ledgerRows, transactions uint64
	if err := client.Conn.QueryRow(ctx, `SELECT count() FROM collector.syslog_reprocess_ledger FINAL
		WHERE event_id=? AND parser_version=?`, eventID, analytics.SyslogParserVersion).
		Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if err := client.Conn.QueryRow(ctx, `SELECT count() FROM collector.antifraud_transactions FINAL
		WHERE device_id=?`, deviceID).Scan(&transactions); err != nil {
		t.Fatal(err)
	}
	if ledgerRows != 1 || transactions != 1 {
		t.Fatalf("ledger=%d transactions=%d, want 1/1", ledgerRows, transactions)
	}
}
