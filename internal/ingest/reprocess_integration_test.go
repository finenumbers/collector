package ingest

import (
	"context"
	"os"
	"testing"
	"time"

	"collector/internal/analytics"
	"collector/internal/equipment"
	"collector/internal/store"

	"github.com/google/uuid"
)

func TestHistoricalSyslogReprocessIsIdempotent(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if address == "" || databaseURL == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR and POSTGRES_TEST_URL are required")
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
	control, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.DB.Close()
	if err := control.Migrate(ctx, "../../migrations/postgres"); err != nil {
		t.Fatal(err)
	}
	actor := store.User{
		ID: uuid.New(), Username: "syslog-reprocess-" + uuid.NewString(), Role: "admin",
	}
	if _, err := control.DB.Exec(ctx, `INSERT INTO users(id,username,password_hash,role)
		VALUES($1,$2,'test-only','admin')`, actor.ID, actor.Username); err != nil {
		t.Fatal(err)
	}
	device, err := control.CreateDevice(ctx, store.NewDevice{
		Name: "syslog-reprocess-" + uuid.NewString(), SourceCategory: equipment.CategoryEquipment,
		TemplateKey: equipment.TemplateEltex3410, Firmware: store.FirmwareScheme3410,
		SyslogSourceIP: "198.51.100.45", Timezone: "Asia/Novosibirsk",
	}, actor, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM devices WHERE id=$1`, device.ID)
		_, _ = control.DB.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actor.ID)
	})
	deviceID, eventID := device.ID, uuid.New()
	event := ParseSyslog(RawSyslog{
		EventID: eventID, DeviceID: deviceID, ReceivedAt: time.Now().UTC(),
		SourceIP: "10.0.0.10", SourcePort: 10003,
		Payload: []byte(`<14> <smg1016m> 17:00:00.1 [INFO] [CREPLAY] RADIUS. ` +
			`Access-Request Acct-Session-Id='replay-session' ` +
			`Cisco-AVPair='xpgk-request-type=check_call'`),
	})
	// Simulate a stale first-parse snapshot. Historical replay must publish the
	// current interpretation without rewriting immutable raw_syslog.
	event.Category = "unknown"
	if err := client.InsertSyslog(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := RunHistoricalSyslogReprocessOnceWithOptions(
		ctx, client, control, false, SyslogReplayOptions{Sleep: time.Nanosecond},
	); err != nil {
		t.Fatal(err)
	}
	if err := RunHistoricalSyslogReprocessOnceWithOptions(
		ctx, client, control, false, SyslogReplayOptions{Sleep: time.Nanosecond},
	); err != nil {
		t.Fatal(err)
	}
	var ledgerRows, transactions, constructs, packets, operations uint64
	if err := client.Conn.QueryRow(ctx, `SELECT count() FROM collector.syslog_reprocess_ledger FINAL
		WHERE event_id=? AND parser_version=?`, eventID, analytics.SyslogParserVersion).
		Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	if err := client.Conn.QueryRow(ctx, `SELECT count() FROM collector.antifraud_lifecycles FINAL
		WHERE device_id=?`, deviceID).Scan(&transactions); err != nil {
		t.Fatal(err)
	}
	if err := client.Conn.QueryRow(ctx, `SELECT count() FROM collector.syslog_constructs FINAL
		WHERE device_id=?`, deviceID).Scan(&constructs); err != nil {
		t.Fatal(err)
	}
	if err := client.Conn.QueryRow(ctx, `SELECT
		(SELECT count() FROM collector.current_antifraud_packets
		 WHERE device_id=? AND parser_version=?),
		(SELECT count() FROM collector.current_antifraud_operations
		 WHERE device_id=? AND parser_version=?)`,
		deviceID, analytics.SyslogParserVersion,
		deviceID, analytics.SyslogParserVersion).Scan(&packets, &operations); err != nil {
		t.Fatal(err)
	}
	if ledgerRows != 1 || transactions != 1 || packets != 1 || operations != 1 {
		t.Fatalf("ledger=%d transactions=%d packets=%d operations=%d, want 1/1/1/1",
			ledgerRows, transactions, packets, operations)
	}
	if constructs != 0 {
		t.Fatalf("disabled replay inserted %d Syslog constructs", constructs)
	}
	jobs, err := control.ListSyslogParserRebuildJobs(ctx, analytics.SyslogParserVersion)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].DeviceID != deviceID || jobs[0].Status != "completed" ||
		jobs[0].ProcessedEvents != jobs[0].TotalEvents || jobs[0].ProcessedEvents != 1 {
		t.Fatalf("unexpected durable replay progress: %#v", jobs)
	}
	var projectionStatus string
	if err := client.Conn.QueryRow(ctx, `SELECT argMax(status,updated_at)
		FROM collector.parser_projection_state
		WHERE device_id=? AND parser_version=?`,
		deviceID, analytics.SyslogParserVersion).Scan(&projectionStatus); err != nil {
		t.Fatal(err)
	}
	if projectionStatus != "active" {
		t.Fatalf("parser projection status=%q, want active", projectionStatus)
	}
	page, err := client.ListEventsPage(ctx, deviceID, "all", "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Category != "radius" {
		t.Fatalf("fallback read did not use current interpretation: %#v", page.Items)
	}
}
