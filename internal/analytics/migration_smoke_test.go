package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestClickHouseMigrationsSmoke(t *testing.T) {
	address := os.Getenv("CLICKHOUSE_TEST_ADDR")
	if address == "" {
		t.Skip("CLICKHOUSE_TEST_ADDR is not set")
	}
	username := os.Getenv("CLICKHOUSE_TEST_USER")
	password := os.Getenv("CLICKHOUSE_TEST_PASSWORD")
	client, err := Open(address, "collector", username, password)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.Migrate(ctx, "../../migrations/clickhouse", MigrationOptions{
		StopBeforeCopy: true,
	}); err != nil {
		t.Fatal(err)
	}
	eventID, deviceID := uuid.New(), uuid.New()
	receivedAt := time.Date(2026, 7, 27, 1, 2, 3, 456789000, time.UTC)
	payload := []byte("raw\x00syslog User-Password=hunter2\n")
	sum := sha256.Sum256(payload)
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.raw_syslog
		(event_id,device_id,received_at,source_ip,source_port,transport,payload,payload_sha256)
		VALUES(?,?,toDateTime64(?,6,'UTC'),?,?,'udp',?,?)`,
		eventID, deviceID, receivedAt.Format("2006-01-02 15:04:05.000000"),
		net.ParseIP("2001:db8::1"), uint16(1514),
		string(payload), hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if err := client.Migrate(ctx, "../../migrations/clickhouse", MigrationOptions{
		LegacyParserJobsChecked: true, StopBeforeCleanup: true,
	}); err != nil {
		t.Fatal(err)
	}
	report, err := client.PreflightLegacySyslogCleanup(ctx, MigrationOptions{
		LegacyParserJobsChecked: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if report.Source.Rows != 1 {
		t.Fatalf("copy digest rows=%d, want 1", report.Source.Rows)
	}
	var copiedEventID, copiedDeviceID uuid.UUID
	var copiedReceivedAt time.Time
	var copiedSourceIP net.IP
	var copiedSourcePort uint16
	var copiedTransport, copiedPayload, copiedHash string
	if err := client.Conn.QueryRow(ctx, `SELECT event_id,device_id,received_at,source_ip,
		source_port,transport,payload,payload_sha256 FROM collector.syslog_messages`).
		Scan(&copiedEventID, &copiedDeviceID, &copiedReceivedAt, &copiedSourceIP,
			&copiedSourcePort, &copiedTransport, &copiedPayload, &copiedHash); err != nil {
		t.Fatal(err)
	}
	if copiedEventID != eventID || copiedDeviceID != deviceID ||
		!copiedReceivedAt.Equal(receivedAt) || !copiedSourceIP.Equal(net.ParseIP("2001:db8::1")) ||
		copiedSourcePort != 1514 || copiedTransport != "udp" ||
		copiedPayload != string(payload) || copiedHash != hex.EncodeToString(sum[:]) {
		t.Fatal("immutable Syslog fields changed during copy")
	}
	if err := client.Conn.Exec(ctx, `ALTER TABLE collector.syslog_messages
		UPDATE payload='corrupted' WHERE event_id=? SETTINGS mutations_sync=1`, eventID); err != nil {
		t.Fatal(err)
	}
	corrupt, err := client.PreflightLegacySyslogCleanup(ctx, MigrationOptions{
		LegacyParserJobsChecked: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if corrupt.Validate() == nil {
		t.Fatal("preflight accepted a corrupted destination payload")
	}
	if err := client.Migrate(ctx, "../../migrations/clickhouse", MigrationOptions{
		LegacyParserJobsChecked: true,
	}); err == nil {
		t.Fatal("destructive cleanup ran after copy corruption")
	}
	var rawStillPresent uint64
	if err := client.Conn.QueryRow(ctx, `SELECT count() FROM system.tables
		WHERE database='collector' AND name='raw_syslog'`).Scan(&rawStillPresent); err != nil {
		t.Fatal(err)
	}
	if rawStillPresent != 1 {
		t.Fatal("raw_syslog was dropped after failed copy verification")
	}
	if err := client.Conn.Exec(ctx, `ALTER TABLE collector.syslog_messages
		UPDATE payload=? WHERE event_id=? SETTINGS mutations_sync=1`, string(payload), eventID); err != nil {
		t.Fatal(err)
	}
	if err := client.Migrate(ctx, "../../migrations/clickhouse", MigrationOptions{
		LegacyParserJobsChecked: true,
	}); err != nil {
		t.Fatal(err)
	}
	var applied uint64
	if err := client.Conn.QueryRow(ctx,
		"SELECT count() FROM collector.schema_migrations").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 29 {
		t.Fatalf("got %d applied migrations, want 29", applied)
	}
	rows, err := client.Conn.Query(ctx, `SELECT name FROM system.tables
		WHERE database='collector' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cdr_antifraud_assignments", "cdr_antifraud_assignments_current",
		"cdr_antifraud_coverage", "cdr_antifraud_coverage_current",
		"cdr_reconciliation_dirty_buckets", "cdr_records", "cdr_time_facts",
		"cdr_time_interpretations",
		"custom_antifraud_call_packets", "custom_antifraud_call_packets_current",
		"custom_antifraud_calls", "custom_antifraud_calls_current",
		"custom_projection_dirty_buckets", "custom_projection_state",
		"custom_radius_exchanges", "custom_radius_exchanges_current",
		"custom_radius_packet_members", "custom_radius_packet_members_current",
		"custom_radius_packets", "custom_radius_packets_current",
		"custom_radius_session_events", "custom_radius_session_events_current", "satel_rtu_cdr",
		"satel_rtu_cdr_time_facts", "schema_migrations", "syslog_messages",
	}
	if !slices.Equal(tables, want) {
		t.Fatalf("remaining tables=%v, want %v", tables, want)
	}
	retryID := uuid.New()
	retry := SyslogMessage{
		EventID: retryID, DeviceID: deviceID, ReceivedAt: receivedAt.Add(time.Second),
		SourceIP: net.ParseIP("2001:db8::2"), SourcePort: 1514, Transport: "udp",
		Payload: []byte("Authorization: Bearer preserve-this-secret"),
	}
	if err := client.InsertSyslogMessagesBatch(ctx, []SyslogMessage{retry}); err != nil {
		t.Fatal(err)
	}
	if err := client.InsertSyslogMessagesBatch(ctx, []SyslogMessage{retry}); err != nil {
		t.Fatal(err)
	}
	var logicalRows uint64
	var storedPayload string
	if err := client.Conn.QueryRow(ctx, `SELECT count(),any(payload)
		FROM collector.syslog_messages FINAL WHERE event_id=?`, retryID).
		Scan(&logicalRows, &storedPayload); err != nil {
		t.Fatal(err)
	}
	if logicalRows != 1 {
		t.Fatalf("retry produced %d logical rows, want 1", logicalRows)
	}
	if storedPayload != string(retry.Payload) {
		t.Fatal("live immutable Syslog persistence changed secret-containing payload bytes")
	}
	var engine string
	if err := client.Conn.QueryRow(ctx, `SELECT engine FROM system.tables
		WHERE database='collector' AND name='syslog_messages'`).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if engine != "ReplacingMergeTree" {
		t.Fatalf("syslog_messages engine=%q, want ReplacingMergeTree", engine)
	}

	bucket := time.Now().UTC().Truncate(time.Hour)
	snapshotID := uuid.New()
	if err := client.Conn.Exec(ctx, `INSERT INTO collector.custom_projection_state
		(device_id,bucket_start,policy_revision,projection_seq,snapshot_id,previous_snapshot_id,
		 marker,watermark_received_at,watermark_event_id,row_count,activated_at,deleted)
		VALUES(?,?,1,1,?,NULL,'active',NULL,NULL,2,now64(6),0)`,
		deviceID, bucket, snapshotID); err != nil {
		t.Fatal(err)
	}
	for index, status := range []string{"blocked", "pending"} {
		if err := client.Conn.Exec(ctx, `INSERT INTO collector.custom_antifraud_calls
			(device_id,bucket_start,snapshot_id,policy_revision,projection_seq,call_id,contract_key,
			 acct_session_id,h323_conf_id,calling,called,status,coverage_state,accounting_start,
			 accounting_stop,session_duration_seconds,ordered_attributes_json,
			 unmatched_provenance_json,orphan_packet_ids,explanation_codes,first_seen_at,last_seen_at,
			 deleted)
			VALUES(?,?,?,1,1,?,?,'','','','',?,'awaiting_cdr',NULL,NULL,NULL,'[]','[]',[],[],
			 now64(6),now64(6),0)`,
			deviceID, bucket, snapshotID, uuid.New(), fmt.Sprintf("call-%d", index), status); err != nil {
			t.Fatal(err)
		}
	}
	dashboard := client.Dashboard(ctx, 24*time.Hour)
	metrics := dashboard.Devices[deviceID]
	if metrics == nil || metrics.Antifraud != 2 || metrics.AntifraudRejected != 1 ||
		metrics.AntifraudIncomplete != 1 {
		t.Fatalf("custom AntiFraud dashboard metrics=%+v, want total/rejected/incomplete 2/1/1",
			metrics)
	}
}
