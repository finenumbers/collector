package analytics

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSatelRTUInsertListStatsAndIdempotency(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	client, err := Open(
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
	deviceID, fileID := uuid.New(), uuid.New()
	t.Cleanup(func() {
		_ = client.PurgeDeviceData(context.Background(), deviceID)
	})
	setup := time.Date(2026, 7, 1, 7, 0, 0, 0, time.UTC)
	connect := setup.Add(2 * time.Second)
	disconnect := connect.Add(10 * time.Second)
	duration := uint64(10000)
	routeRetries := uint64(2)
	record := SatelRTURecord{
		RecordID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(deviceID.String()+"|synthetic")),
		DeviceID: deviceID, FileID: fileID, RowNumber: 1, IngestedAt: time.Now().UTC(),
		ParserVersion: SatelRTUParserVersion, TemplateKey: "satel-rtu-cdr-v1",
		CDRID: "synthetic", CDRDate: &setup, SetupTime: &setup, ConnectTime: &connect,
		DisconnectTime: &disconnect, DurationMS: &duration, Outcome: "answered",
		InANI: "searchable-user", InDNIS: "service", SrcName: "route-in",
		DstName: "route-out", DPName: "main", DisconnectCode: 65546,
		InLRN: "lrn-in", RetrievedLRN: "lrn-retrieved", LRN: "lrn-main",
		ExtLRN: "lrn-external", OutLRN: "lrn-out", LNPServer: "lnp.synthetic.invalid",
		RouteRetries: &routeRetries, InCPC: "ordinary", OutCPC: "ordinary",
		DisconnectText: "TS, 10 - BYE received", DisconnectSuccess: true,
		RawFields: map[string]string{
			"cdr_date": "2026-07-01 10:00:00", "setup_time": "2026-07-01 10:00:00",
			"connect_time":    "2026-07-01 10:00:02",
			"disconnect_time": "2026-07-01 10:00:12",
		},
		SourceTimezone: "Europe/Moscow", SourceUTCOffsetMinutes: 180,
		TimezoneRevision: 1,
	}
	if err := client.InsertSatelRTUBatch(ctx, []SatelRTURecord{record}); err != nil {
		t.Fatal(err)
	}
	record.IngestedAt = record.IngestedAt.Add(time.Millisecond)
	if err := client.InsertSatelRTUBatch(ctx, []SatelRTURecord{record}); err != nil {
		t.Fatal(err)
	}
	var count uint64
	if err := client.Conn.QueryRow(ctx,
		`SELECT count() FROM collector.satel_rtu_cdr FINAL WHERE device_id=?`,
		deviceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("idempotent insert produced %d FINAL rows", count)
	}
	page, err := client.ListSatelRTUCallsPage(ctx, deviceID, "searchable", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Outcome != "answered" ||
		page.Items[0].SetupTimeLocal == "" || page.Items[0].LRN != "lrn-main" ||
		page.Items[0].LNPServer != "lnp.synthetic.invalid" ||
		page.Items[0].RouteRetries == nil || *page.Items[0].RouteRetries != 2 {
		t.Fatalf("unexpected Satel page: %+v", page)
	}
	stats, err := client.SatelRTUStats(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Calls24h != 0 {
		// The synthetic timestamp is intentionally old relative to the test run.
		t.Fatalf("old synthetic call included in 24h stats: %+v", stats)
	}
	if err := client.ReinterpretSatelRTUTimes(ctx, deviceID, 2, "UTC"); err != nil {
		t.Fatal(err)
	}
	var facts uint64
	if err := client.Conn.QueryRow(ctx, `SELECT count() FROM collector.satel_rtu_cdr_time_facts
		FINAL WHERE device_id=? AND timezone_revision=2`, deviceID).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if facts != 1 {
		t.Fatalf("timezone reparse produced %d facts", facts)
	}
}
