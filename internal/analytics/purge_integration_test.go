package analytics

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPurgeDeviceDataRemovesEveryDeviceScopedTable(t *testing.T) {
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
	deviceID, otherDeviceID := uuid.New(), uuid.New()
	now := time.Now().UTC()
	insertRaw := func(device uuid.UUID) {
		t.Helper()
		if err := client.Conn.Exec(ctx, `INSERT INTO collector.raw_syslog
			(event_id,device_id,received_at,source_ip,source_port,transport,payload,
			 payload_sha256,header_format,parser_version,parse_status,category,component,message)
			VALUES(?,?,?,toIPv6('127.0.0.1'),514,'udp','test',?,'rfc3164',?,'parsed',
			 'system_journal','test','test')`,
			uuid.New(), device, now, strings.Repeat("0", 64), SyslogParserVersion); err != nil {
			t.Fatal(err)
		}
	}
	insertRaw(deviceID)
	insertRaw(otherDeviceID)
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.cdr_records
		(record_id,device_id,file_id,row_number,ingested_at,sequence_number)
		VALUES(?,?,?,?,?,?)`, uuid.New(), deviceID, uuid.New(), 1, now, "purge-test"); err != nil {
		t.Fatal(err)
	}
	if err := client.PurgeDeviceData(ctx, deviceID); err != nil {
		t.Fatal(err)
	}
	var remaining uint64
	if err := client.Conn.QueryRow(ctx,
		`SELECT count() FROM collector.raw_syslog WHERE device_id=?`, otherDeviceID).
		Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("purge removed another SMG: remaining=%d", remaining)
	}
	if err := client.PurgeDeviceData(ctx, deviceID); err != nil {
		t.Fatalf("repeated purge must be idempotent: %v", err)
	}
	if err := client.PurgeDeviceData(ctx, otherDeviceID); err != nil {
		t.Fatal(err)
	}
}
