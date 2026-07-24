package analytics

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAntifraudLifecycleClickHouse(t *testing.T) {
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
	deviceID := uuid.New()
	now := time.Now().UTC().Add(-time.Minute)
	request := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now,
		SourceIP: net.ParseIP("10.0.0.10"), SourcePort: 10003,
		Payload: []byte("Access-Request"), HeaderFormat: "eltex-trace",
		ParseStatus: "parsed", Category: "radius", Component: "RADIUS",
		Message: "Access-Request",
		Attributes: map[string]string{
			"call_context": "C0TEST1", "packet_code": "access-request",
			"packet_direction": "request", "packet_identifier": "157",
			"acct_session_id": "session 42", "xpgk_request_type": "check_call",
			"is_antifraud": "true", "calling_station_id": "73832888803",
			"called_station_id": "74951234567",
		},
	}
	response := request
	response.EventID = uuid.New()
	response.ReceivedAt = now.Add(165 * time.Millisecond)
	response.Payload = []byte("Access-Reject")
	response.Message = "Access-Reject"
	response.Attributes = map[string]string{
		"call_context": "C0TEST1", "packet_code": "access-reject",
		"packet_direction": "response", "packet_identifier": "157",
		"result": "reject", "latency_ms": "165",
	}
	for _, event := range []SyslogEvent{request, response} {
		if err := client.InsertSyslog(ctx, event); err != nil {
			t.Fatal(err)
		}
		if err := client.ProcessSyslogDerived(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	recordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: recordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 1,
		IngestedAt: now, SequenceNumber: "20260724170000-1", BootEpoch: "20260724170000",
		Sequence: 1, SetupTime: &now, RadiusSessionID: "session 42",
		RadiusSessionIDNormalized: "session42", RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	candidateRecordID := uuid.New()
	if err := client.InsertCDRBatch(ctx, []CDRRecord{{
		RecordID: candidateRecordID, DeviceID: deviceID, FileID: uuid.New(), RowNumber: 2,
		IngestedAt: now, SequenceNumber: "20260724170000-2", BootEpoch: "20260724170000",
		Sequence: 2, SetupTime: &now, IncomingCgPN: "73832888803",
		RawFields: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	sipEvent := SyslogEvent{
		EventID: uuid.New(), DeviceID: deviceID, ReceivedAt: now.Add(time.Second),
		SourceIP: net.ParseIP("10.0.0.10"), SourcePort: 10003,
		Payload: []byte("SIP connected"), HeaderFormat: "eltex-trace",
		ParseStatus: "parsed", Category: "sip", Component: "SIP",
		Message: "connected", Attributes: map[string]string{"call_context": "C0TEST1"},
	}
	if err := client.InsertSyslog(ctx, sipEvent); err != nil {
		t.Fatal(err)
	}
	if err := client.ProcessSyslogDerived(ctx, sipEvent); err != nil {
		t.Fatal(err)
	}
	page, err := client.ListAntifraudPage(ctx, deviceID, "", 100, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("got %d lifecycles, want 1", len(page.Items))
	}
	item := page.Items[0]
	if item.Decision != "reject" || item.Q850Cause == nil || *item.Q850Cause != 21 ||
		item.LegCount != 1 || item.Completeness != "complete" {
		t.Fatalf("invalid lifecycle: %#v", item)
	}
	timeline, err := client.AntifraudTimeline(ctx, deviceID, item.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(timeline) != 2 {
		t.Fatalf("got %d timeline events, want 2", len(timeline))
	}
	callTimeline, err := client.CallTimeline(ctx, deviceID, recordID)
	if err != nil {
		t.Fatal(err)
	}
	if len(callTimeline) < 3 {
		t.Fatalf("CDR did not receive complete AntiFraud evidence: %d", len(callTimeline))
	}
	var candidateCount, candidateLinks uint64
	if err := client.Conn.QueryRow(ctx, `SELECT count()
		FROM collector.call_correlation_candidates FINAL
		WHERE device_id=? AND cdr_record_id=?`, deviceID, candidateRecordID).
		Scan(&candidateCount); err != nil {
		t.Fatal(err)
	}
	if err := client.Conn.QueryRow(ctx, `SELECT count()
		FROM collector.call_event_links
		WHERE device_id=? AND cdr_record_id=?`, deviceID, candidateRecordID).
		Scan(&candidateLinks); err != nil {
		t.Fatal(err)
	}
	if candidateCount != 1 || candidateLinks != 0 {
		t.Fatalf("ambiguous evidence must remain unlinked: candidates=%d links=%d",
			candidateCount, candidateLinks)
	}
	stats, err := client.Stats(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Antifraud24h != 1 || stats.AntifraudRejected24h != 1 ||
		stats.UnlinkedCalls24h != 1 {
		t.Fatalf("incorrect lifecycle coverage: %#v", stats)
	}
	diagnostics, err := client.SyslogDiagnostics(ctx, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics.RawEvents24h != 3 || diagnostics.Classified24h != 3 ||
		diagnostics.AntifraudComplete != 1 {
		t.Fatalf("incorrect parser/lifecycle diagnostics: %#v", diagnostics)
	}
}
